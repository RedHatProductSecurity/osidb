"""
    serialize flaw model
"""

import logging
import uuid
from collections import defaultdict
from distutils.util import strtobool
from typing import Dict, List, Tuple

from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import BadRequest
from django.db.models import Max
from drf_spectacular.utils import extend_schema_field, extend_schema_serializer
from rest_framework import serializers

from apps.bbsync.mixins import BugzillaSyncMixin
from apps.osim.serializers import WorkflowModelSerializer
from apps.taskman.constants import JIRA_TASKMAN_AUTO_SYNC_FLAW, SYNC_REQUIRED_FIELDS
from apps.taskman.mixins import JiraTaskSyncMixin

from .core import generate_acls
from .exceptions import DataInconsistencyException
from .helpers import ensure_list
from .mixins import ACLMixin, TrackingMixin
from .models import (
    Affect,
    AffectCVSS,
    Erratum,
    Flaw,
    FlawAcknowledgment,
    FlawComment,
    FlawCVSS,
    FlawMeta,
    FlawReference,
    Package,
    PackageVer,
    Profile,
    PsUpdateStream,
    Tracker,
)

logger = logging.getLogger(__name__)


def parse_fields(fields: List[str]) -> Tuple[List[str], Dict[str, List[str]]]:
    """
    Parse each include/exclude item into list of current level fields
    and dict of next level fields.

    Example:
        [uuid, affects, affects.uuid, affects.trackers.uuid]

        ->

        ["uuid", "affects"]
        {"affects": ["uuid", "trackers.uuid"]}

    """

    current_level_fields = set()
    next_level_fields = defaultdict(set)

    for field in fields:
        if "." in field:
            related_field, next_level_field = field.split(".", maxsplit=1)
            next_level_fields[related_field].add(next_level_field)
        else:
            current_level_fields.add(field)

    return (
        list(current_level_fields),
        {key: list(value) for key, value in next_level_fields.items()},
    )


class IncludeExcludeFieldsMixin(serializers.ModelSerializer):
    """
    Mixin for include/exclude fields logic with nested serializers

    include_fields and exclude_fields are obtained either from request or in case
    of the nested serializer from the context which is passed from the parent
    serializer

    Filtering on parent serializer:
        include_fields=uuid,cve_id

    Filtering on nested serializer:
        include_fields=affects.uuid,affects.trackers

    NOTE: when this serializer is used for API view that view also needs to be
    decorated with either `extend_schema_view` decorator describing the parameters
    manually or use shortcut `include_exclude_fields_extend_schema_view` decorator
    """

    def __init__(self, *args, **kwargs):
        # Instantiate the superclass normally
        super().__init__(*args, **kwargs)

        request = self.context.get("request")

        # Get include/exclude fields from request
        if request:
            include_fields_param = request.query_params.get("include_fields")
            exclude_fields_param = request.query_params.get("exclude_fields")

            include_fields = (
                include_fields_param.split(",") if include_fields_param else []
            )
            exclude_fields = (
                exclude_fields_param.split(",") if exclude_fields_param else []
            )

        # Get include/exclude fields from context passed from parent serializer
        else:
            include_fields = self.context.get("include_fields", [])
            exclude_fields = self.context.get("exclude_fields", [])

        (
            self._include_fields,
            self._next_level_include_fields,
        ) = parse_fields(include_fields)

        (
            self._exclude_fields,
            self._next_level_exclude_fields,
        ) = parse_fields(exclude_fields)

        # Drop fields based on include/exclude fields
        existing_fields = set(self.fields)
        for field_name in existing_fields:
            if not self._is_field_visible(field_name):
                self.fields.pop(field_name, None)

    def _is_field_visible(self, field: str) -> bool:
        """Get field visibility based on include/exclude fields logic"""
        # Field is needed for next level include fields, don't drop it
        if field in self._next_level_include_fields:
            return True

        # Include fields on current level were given and field is not in it, drop it
        elif self._include_fields and field not in self._include_fields:
            return False

        # Field is in exclude fields and not in include fields, drop it
        elif field in self._exclude_fields and field not in self._include_fields:
            return False

        # Include fields on current level were not given however there are
        # next level include fields, drop the field
        elif not self._include_fields and self._next_level_include_fields:
            return False

        else:
            return True


class IncludeMetaAttrMixin(serializers.ModelSerializer):
    """
    Mixin for include meta attr fields logic with nested serializers

    include_meta_attr is obtained either from request or in case
    of the nested serializer from the context which is passed from the parent
    serializer

    Filtering on parent serializer:
        include_meta_attr=bz_id,cwe,checklists

    Filtering on nested serializer:
        include_meta_attr=affects.components,affects.trackers.bz_id

    NOTE: when this serializer is used for API view that view also needs to be
    decorated with either `extend_schema_view` decorator describing the parameters
    manually or use shortcut `include_meta_attr_extend_schema_view` decorator
    """

    def __init__(self, *args, **kwargs):
        # Instantiate the superclass normally
        super().__init__(*args, **kwargs)

        request = self.context.get("request")

        # Get include meta attr from request
        if request:
            include_meta_attr_param = request.query_params.get("include_meta_attr")

            include_meta_attr = (
                include_meta_attr_param.split(",") if include_meta_attr_param else []
            )
        # Get include meta attr from context passed from parent serializer
        else:
            include_meta_attr = self.context.get("include_meta_attr")

        if include_meta_attr is not None:
            (
                self._include_meta_attr,
                self._next_level_include_meta_attr,
            ) = parse_fields(include_meta_attr)

            if not self._include_meta_attr:
                # No meta_attr keys specified, drop meta_attr field
                self.fields.pop("meta_attr", None)

    def get_meta_attr(self, obj):
        """Filter meta_attr field based on the given keys to include"""
        meta_attr = obj.meta_attr
        if "*" in self._include_meta_attr:
            return meta_attr
        else:
            return {
                key: value
                for key, value in meta_attr.items()
                if key in self._include_meta_attr
            }


class UpdatedDateTimeField(serializers.DateTimeField):
    def validate_empty_values(self, data):
        """
        skip updated timestamp validation on create
        """
        if self.context["request"].method == "POST":
            return (True, None)
        return super().validate_empty_values(data)


class TrackingMixinSerializer(serializers.ModelSerializer):
    """TrackingMixin class serializer"""

    created_dt = serializers.DateTimeField(read_only=True)
    updated_dt = UpdatedDateTimeField(
        help_text=(
            "The updated_dt timestamp attribute is mandatory "
            "on update as it is used to detect mit-air collisions."
        ),
    )

    class Meta:
        model = TrackingMixin
        fields = ["created_dt", "updated_dt"]
        abstract = True


class ErratumSerializer(
    IncludeExcludeFieldsMixin,
    TrackingMixinSerializer,
):
    """Erratum serializer"""

    et_id = serializers.IntegerField(read_only=True)
    advisory_name = serializers.CharField(read_only=True)
    shipped_dt = serializers.DateTimeField(read_only=True)

    class Meta:
        """filter fields"""

        model = Erratum
        fields = [
            "et_id",
            "advisory_name",
            "shipped_dt",
        ] + TrackingMixinSerializer.Meta.fields


class EmbargoedField(serializers.BooleanField):
    """The embargoed boolean attribute is technically read-only as it just indirectly
    modifies the ACLs but is mandatory as it controls the access to the resource."""

    def to_representation(self, value):
        return value.is_embargoed

    def run_validation(self, data):
        # Run base Boolean field validation, ACL validation and then
        # raise SkipField to not include this field in validated data
        # since we don't have `embargoed` field to write in
        data = super().run_validation(data)
        self.validate_acl(data)
        raise serializers.SkipField()

    def validate_acl(self, embargoed):
        acl_read = (
            settings.EMBARGO_READ_GROUP if embargoed else settings.PUBLIC_READ_GROUPS
        )
        acl_write = (
            settings.EMBARGO_WRITE_GROUP if embargoed else settings.PUBLIC_WRITE_GROUP
        )
        acl_read, acl_write = ensure_list(acl_read), ensure_list(acl_write)

        acls = [group.name for group in self.context["request"].user.groups.all()]
        for acl in acl_read + acl_write:
            # this is a temporary safeguard with a very simple philosophy that one cannot
            # give access to something (s)he does not have access to but possibly in the future
            # we will want some more clever handling like ProdSec can grant anything etc.
            if acl not in acls:
                raise serializers.ValidationError(
                    f"Cannot provide access for the LDAP group without being a member: {acl}"
                )


class ACLMixinSerializer(serializers.ModelSerializer):
    """
    ACLMixin class serializer
    translates embargoed boolean to ACLs
    """

    embargoed = EmbargoedField(
        source="*",
        help_text=(
            "The embargoed boolean attribute is technically read-only as it just indirectly "
            "modifies the ACLs but is mandatory as it controls the access to the resource."
        ),
    )

    class Meta:
        abstract = True
        fields = ["embargoed"]
        model = ACLMixin

    def hash_acl(self, acl):
        """
        convert ACL names to hashed UUIDs
        """
        return [uuid.UUID(ac) for ac in generate_acls(acl)]

    def get_acls(self, embargoed):
        """
        generate ACLs based on embargo status
        """
        acl_read = (
            settings.EMBARGO_READ_GROUP if embargoed else settings.PUBLIC_READ_GROUPS
        )
        acl_write = (
            settings.EMBARGO_WRITE_GROUP if embargoed else settings.PUBLIC_WRITE_GROUP
        )
        acl_read, acl_write = ensure_list(acl_read), ensure_list(acl_write)
        return self.hash_acl(acl_read), self.hash_acl(acl_write)

    def embargoed2acls(self, validated_data):
        """
        process validated data converting embargoed status into the ACLs
        """
        # Already validated in EmbargoedField
        embargoed = self.context["request"].data.get("embargoed")
        if isinstance(embargoed, str):
            embargoed = bool(strtobool(embargoed))

        acl_read, acl_write = self.get_acls(embargoed)
        validated_data["acl_read"] = acl_read
        validated_data["acl_write"] = acl_write

        return validated_data

    def create(self, validated_data):
        validated_data = self.embargoed2acls(validated_data)
        return super().create(validated_data)

    def update(self, instance, validated_data):
        validated_data = self.embargoed2acls(validated_data)
        return super().update(instance, validated_data)


class BugzillaAPIKeyMixin:
    """
    simple mixin providing the Bugzilla API key getter to be shared easily
    """

    def get_bz_api_key(self):
        bz_api_key = self.context["request"].META.get("HTTP_BUGZILLA_API_KEY")
        if not bz_api_key:
            raise serializers.ValidationError(
                {"Bugzilla-Api-Key": "This HTTP header is required."}
            )
        return bz_api_key


class JiraAPIKeyMixin:
    """
    simple mixin providing the Jira API key getter to be shared easily
    """

    def get_jira_token(self):
        jira_token = self.context["request"].META.get("HTTP_JIRA_API_KEY")
        if not jira_token:
            raise serializers.ValidationError(
                {"Jira-Api-Key": "This HTTP header is required."}
            )
        return jira_token


class TrackerSerializer(
    ACLMixinSerializer,
    BugzillaAPIKeyMixin,
    IncludeExcludeFieldsMixin,
    IncludeMetaAttrMixin,
    JiraAPIKeyMixin,
    TrackingMixinSerializer,
):
    """Tracker serializer"""

    # All currently used keys in Tracker.meta_attr used for SwaggerUI population,
    # whenever we introduce new key, which users might be interested in, we should
    # add it to this tuple.
    #
    # See osidb/helpers.py::get_unique_meta_attr_keys for listing all existing keys
    # in the DB
    META_ATTR_KEYS = (
        "bz_id",
        "owner",
        "qe_owner",
        "ps_component",
        "ps_module",
        "ps_update_stream",
        "resolution",
        "status",
    )

    errata = serializers.SerializerMethodField()
    meta_attr = serializers.SerializerMethodField()

    @extend_schema_field(ErratumSerializer(many=True))
    def get_errata(self, obj):
        """erratum serializer getter"""
        context = {
            "include_fields": self._next_level_include_fields.get("errata", []),
            "exclude_fields": self._next_level_exclude_fields.get("errata", []),
        }

        serializer = ErratumSerializer(
            instance=obj.errata.all(), many=True, context=context
        )
        return serializer.data

    @extend_schema_field(
        {
            "type": "object",
            "properties": {key: {"type": "string"} for key in META_ATTR_KEYS},
        }
    )
    def get_meta_attr(self, obj):
        return super().get_meta_attr(obj)

    class Meta:
        """filter fields"""

        model = Tracker
        fields = (
            [
                "affects",
                "errata",
                "external_system_id",
                "meta_attr",
                "ps_update_stream",
                "status",
                "resolution",
                "type",
                "uuid",
            ]
            + ACLMixinSerializer.Meta.fields
            + TrackingMixinSerializer.Meta.fields
        )
        read_only_fields = [
            "external_system_id",
            "type",
        ]

    def create(self, validated_data):
        """
        perform the ordinary instance create
        with providing the API keys while saving
        """
        # transform the embargoed status to the ACLs
        validated_data = ACLMixinSerializer.embargoed2acls(self, validated_data)

        try:
            # determine the tracker type from the PS update stream
            ps_update_stream = PsUpdateStream.objects.get(
                name=validated_data["ps_update_stream"]
            )
            validated_data["type"] = Tracker.BTS2TYPE[
                ps_update_stream.ps_module.bts_name
            ]
        except PsUpdateStream.DoesNotExist:
            raise serializers.ValidationError(
                {
                    "ps_update_stream": "Tracker must be associated with a valid PS update stream"
                }
            )

        affects = validated_data.pop("affects", [])
        instance = self.Meta.model(**validated_data)
        # first save the instance to the local DB only
        # so we can make the links before the backend sync
        instance.save()
        for affect in affects:
            instance.affects.add(affect)

        instance.save(
            bz_api_key=self.get_bz_api_key(), jira_token=self.get_jira_token()
        )

        return instance

    def update(self, instance, validated_data):
        """
        perform the ordinary instance update
        with providing the API keys while saving
        """
        # transform the embargoed status to the ACLs
        validated_data = ACLMixinSerializer.embargoed2acls(self, validated_data)

        # update the relations by simply recreating them
        # which will both delete the old and add the new
        instance.affects.clear()
        for affect in validated_data.pop("affects", []):
            instance.affects.add(affect)

        # update the attributes
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save(
            bz_api_key=self.get_bz_api_key(), jira_token=self.get_jira_token()
        )

        return instance


@extend_schema_serializer(exclude_fields=["external_system_id"])
class TrackerPostSerializer(TrackerSerializer):
    # extra serializer for POST request to exclude
    # not yet existing but otherwise mandatory fields
    pass


class MetaSerializer(ACLMixinSerializer, TrackingMixinSerializer):
    """FlawMeta serializer"""

    class Meta:
        """filter fields"""

        model = FlawMeta
        fields = (
            [
                "uuid",
                "type",
                "meta_attr",
            ]
            + ACLMixinSerializer.Meta.fields
            + TrackingMixinSerializer.Meta.fields
        )


class CommentSerializer(TrackingMixinSerializer):
    """FlawComment serializer for use by FlawSerializer"""

    class Meta:
        """filter fields"""

        model = FlawComment
        fields = [
            "uuid",
            "type",
            "external_system_id",
            "order",
            "meta_attr",
        ] + TrackingMixinSerializer.Meta.fields


class BugzillaBareSyncMixinSerializer(BugzillaAPIKeyMixin, serializers.ModelSerializer):
    """
    Serializer mixin class implementing special handling of model saving
    required to perform Bugzilla sync as part of the save procedure.
    This class is intended for serializer classes that instantiate and update
    the models themselves and only need the mixin for the special bugzilla sync
    save behavior.
    """

    def create(self, instance):
        """
        Sync the already-created instance to bugzilla and sync&save it back to
        the database.
        """
        instance.save(bz_api_key=self.get_bz_api_key())
        return instance

    def update(self, instance):
        """
        Sync the already-created instance to bugzilla and sync&save it back to
        the database.
        """
        instance.save(bz_api_key=self.get_bz_api_key())
        return instance

    class Meta:
        model = BugzillaSyncMixin
        abstract = True


class BugzillaSyncMixinSerializer(BugzillaBareSyncMixinSerializer):
    """
    serializer mixin class implementing special handling of the models
    which need to perform Bugzilla sync as part of the save procedure
    """

    def create(self, validated_data):
        """
        perform the ordinary instance create
        with providing BZ API key while saving
        """
        # NOTE: This won't work for many-to-many fields as
        # some logic from original .create() was overwritten.
        # Consider BugzillaBareSyncMixinSerializer for these.

        instance = self.Meta.model(**validated_data)
        instance = super().create(instance)
        return instance

    def update(self, instance, validated_data):
        """
        perform the ordinary instance update
        with providing BZ API key while saving
        """
        # NOTE: This won't work for many-to-many fields as
        # some logic from original .create() was overwritten
        # Consider BugzillaBareSyncMixinSerializer for these.

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance = super().update(instance)
        return instance

    class Meta:
        model = BugzillaSyncMixin
        abstract = True


class JiraTaskSyncMixinSerializer(JiraAPIKeyMixin, serializers.ModelSerializer):
    """
    serializer mixin class implementing special handling of the models
    which need to perform Jira sync as part of the save procedure
    """

    def create(self, validated_data):
        """
        perform the ordinary instance create
        with providing Jira token while saving
        """
        instance = super().create(validated_data)
        if JIRA_TASKMAN_AUTO_SYNC_FLAW:
            instance.tasksync(jira_token=self.get_jira_token(), force_creation=True)
        return instance

    def update(self, instance, validated_data):
        """
        perform the ordinary instance create
        with providing Jira token while saving
        """
        # to allow other mixings to override update we call parent's update method
        # and validate if an important change were made forcing a sync when it is needed
        sync_required = any(
            field in validated_data
            and getattr(instance, field) != validated_data[field]
            for field in SYNC_REQUIRED_FIELDS
        )
        updated_instance = super().update(instance, validated_data)
        if JIRA_TASKMAN_AUTO_SYNC_FLAW and sync_required:
            updated_instance.tasksync(
                jira_token=self.get_jira_token(), force_update=True
            )
        return updated_instance

    class Meta:
        model = JiraTaskSyncMixin
        abstract = True


class AffectCVSSSerializer(
    ACLMixinSerializer,
    BugzillaSyncMixinSerializer,
    IncludeExcludeFieldsMixin,
    TrackingMixinSerializer,
):
    """AffectCVSS serializer"""

    cvss_version = serializers.CharField(source="version")

    class Meta:
        """filter fields"""

        model = AffectCVSS
        fields = (
            ["affect", "comment", "cvss_version", "issuer", "score", "uuid", "vector"]
            + ACLMixinSerializer.Meta.fields
            + TrackingMixinSerializer.Meta.fields
        )


@extend_schema_serializer(exclude_fields=["affect", "updated_dt"])
class AffectCVSSPostSerializer(AffectCVSSSerializer):
    # Extra serializer for POST request as there is no last update
    # timestamp but we need to make the field mandatory otherwise.
    # Flaw shouldn't be required in the body (already included in the path).
    pass


@extend_schema_serializer(exclude_fields=["affect"])
class AffectCVSSPutSerializer(AffectCVSSSerializer):
    # Extra serializer for PUT request because affect shouldn't be
    # required in the body (already included in the path).
    pass


@extend_schema_serializer(
    deprecate_fields=["cvss2", "cvss2_score", "cvss3", "cvss3_score"]
)
class AffectSerializer(
    ACLMixinSerializer,
    BugzillaSyncMixinSerializer,
    TrackingMixinSerializer,
    IncludeExcludeFieldsMixin,
    IncludeMetaAttrMixin,
):
    """Affect serializer"""

    # All currently used keys in Affect.meta_attr used for SwaggerUI population,
    # whenever we introduce new key, which users might be interested in, we should
    # add it to this tuple.
    #
    # See osidb/helpers.py::get_unique_meta_attr_keys for listing all existing keys
    # in the DB
    META_ATTR_KEYS = (
        "affectedness",
        "component",
        "cvss2",
        "cvss3",
        "impact",
        "module_name",
        "module_stream",
        "ps_component",
        "ps_module",
        "resolution",
    )

    trackers = serializers.SerializerMethodField()
    meta_attr = serializers.SerializerMethodField()
    cvss_scores = AffectCVSSSerializer(many=True, read_only=True)

    @extend_schema_field(
        {
            "type": "object",
            "properties": {key: {"type": "string"} for key in META_ATTR_KEYS},
        }
    )
    def get_meta_attr(self, obj):
        return super().get_meta_attr(obj)

    @extend_schema_field(TrackerSerializer(many=True))
    def get_trackers(self, obj):
        """tracker serializer getter"""
        context = {
            "include_fields": self._next_level_include_fields.get("trackers", []),
            "exclude_fields": self._next_level_exclude_fields.get("trackers", []),
            "include_meta_attr": self._next_level_include_meta_attr.get("trackers", []),
        }

        serializer = TrackerSerializer(
            instance=obj.trackers.all(), many=True, context=context
        )
        return serializer.data

    class Meta:
        """filter fields"""

        model = Affect
        fields = (
            [
                "uuid",
                "flaw",
                "type",
                "affectedness",
                "resolution",
                "ps_module",
                "ps_component",
                "impact",
                "cvss2",
                "cvss2_score",
                "cvss3",
                "cvss3_score",
                "trackers",
                "meta_attr",
                "delegated_resolution",
                "cvss_scores",
            ]
            + ACLMixinSerializer.Meta.fields
            + TrackingMixinSerializer.Meta.fields
        )


@extend_schema_serializer(exclude_fields=["updated_dt"])
class AffectPostSerializer(AffectSerializer):
    # extra serializer for POST request as there is no last update
    # timestamp but we need to make the field mandatory otherwise
    pass


@extend_schema_serializer(deprecate_fields=["status"])
class PackageVerSerializer(serializers.ModelSerializer):
    """
    PackageVer model serializer for read-only use in FlawSerializer via
    PackageVerSerializer.
    """

    # Deprecated field, kept for schema backwards compatibility.
    status = serializers.ReadOnlyField(default="UNAFFECTED")

    class Meta:
        model = PackageVer
        fields = ["version", "status"]


class PackageSerializer(serializers.ModelSerializer):
    """package_versions (Package model) serializer for read-only use in FlawSerializer."""

    versions = PackageVerSerializer(many=True)

    class Meta:
        model = Package
        fields = ["package", "versions"]


@extend_schema_field({"type": "array", "items": {"type": "string"}})
class FlawAffectsTrackersField(serializers.Field):
    """All Tracker keys from all Flaw Affects are serialized into one list"""

    def to_representation(self, value):
        trackers = set()
        for affect in value.affects.all():
            trackers.update(
                [tracker.external_system_id for tracker in affect.trackers.all()]
            )
        return list(trackers)


class FlawAcknowledgmentSerializer(
    ACLMixinSerializer,
    BugzillaSyncMixinSerializer,
    IncludeExcludeFieldsMixin,
    IncludeMetaAttrMixin,
    TrackingMixinSerializer,
):
    """FlawAcknowledgment serializer"""

    class Meta:
        """filter fields"""

        model = FlawAcknowledgment
        fields = (
            ["name", "affiliation", "from_upstream", "flaw", "uuid"]
            + ACLMixinSerializer.Meta.fields
            + TrackingMixinSerializer.Meta.fields
        )


@extend_schema_serializer(exclude_fields=["flaw"])
class FlawAcknowledgmentPutSerializer(FlawAcknowledgmentSerializer):
    # Extra serializer for PUT request because flaw shouldn't be
    # required in the body (already included in the path).
    pass


@extend_schema_serializer(exclude_fields=["flaw", "updated_dt"])
class FlawAcknowledgmentPostSerializer(FlawAcknowledgmentSerializer):
    # Extra serializer for POST request as there is no last update
    # timestamp but we need to make the field mandatory otherwise.
    # Flaw shouldn't be required in the body (already included in the path).
    pass


class FlawVersionSerializer(
    IncludeExcludeFieldsMixin,
):
    """PackageVer serializer used by FlawPackageVersionSerializer."""

    class Meta:
        model = PackageVer
        fields = ["version"]


class FlawPackageVersionSerializerMixin:
    """
    This mixin enables FlawPackageVersionSerializer to insert Package (and
    nested PackageVer) deserialization into the MRO between ACLMixinSerializer
    and BugzillaBareSyncMixinSerializer.

    Performs deserialization of PackageVer nested within Package because
    Django doesn't provide out-of-the-box nested write serialization.
    """

    def create(self, validated_data):
        """
        Handles POST HTTP to add one or more package versions to the specified Flaw.

        # - Package and version are treated as a unit, so even if the given
        #   package name is already tracked, the version(s) provided in the
        #   request are added.
        # - If a package & version already exist, it is not touched and the POST
        #   request returns the UUID of the respective Package object.
        # - If a package already exists, but some of the versions provided in the
        #   request don't, the Package object is preserved, its existing versions
        #   are preserved and the versions provided in the request are added.
        """

        # NOTE: This method needs to have this line from
        #       ACLMixinSerializer.create() already executed at this point:
        #           validated_data = self.embargoed2acls(validated_data)
        #       This is ensured by the MRO of
        #       FlawPackageVersionSerializer.create().

        versions = validated_data.pop("versions")

        package_instance = Package.objects.create_package(**validated_data)
        for version in versions:
            version = version["version"]
            PackageVer.objects.get_or_create(
                version=version,
                package=package_instance,
            )

        # NOTE: Bugzilla sync needs to have the equivalent of these 2 lines from
        #       BugzillaBareSyncMixinSerializer.create() executed before the return:
        #           bzkey = self._BugzillaBareSyncMixinSerializer__get_bz_api_key()
        #           package_instance.save(bz_api_key=bzkey)
        #       This is ensured by the MRO of
        #       FlawPackageVersionSerializer.create() and the following line:
        package_instance = super().create(package_instance)

        return package_instance

    def update(self, retrieved_package_instance, validated_data):
        """
        Handles PUT HTTP to perform update of the requested Package instance and of
        the associated PackageVer instances.

        # - The UUID of the Package instance is provided in the URL of the HTTP
        #   request. This instance is updated based on the data provided in the request.
        # - If the package name changes, the UUID of the Package instance changes.
        # - If the package name in the request collides with another already-existing
        #   Package object, the request-supplied UUID is deleted and the returned UUID
        #   is the UUID of the Package object with the request-supplied package name.
        # - Versions are replaced by the versions provided in the request.
        """

        # NOTE: This method needs to have this line from
        #       ACLMixinSerializer.update() already executed at this point:
        #           validated_data = self.embargoed2acls(validated_data)
        #       This is ensured by the MRO of
        #       FlawPackageVersionSerializer.update().

        versions = validated_data.pop("versions")
        package = validated_data.pop("package")
        flaw = validated_data.pop("flaw")

        # NOTE: "package_instance" contains request-provided "updated_dt",
        #       but "retrieved_package_instance" contains database-stored
        #       "updated_dt".
        # NOTE: We must continue with "package_instance" so that TrackingMixin
        #       validates the "updated_dt" timestamp correctly.
        # NOTE: "retrieved_package_instance" was found based on UUID, whereas
        #       "package_instance" is searched based on (flaw, package).
        package_instance = Package.objects.create_package(
            flaw=flaw,
            package=package,
            **validated_data,
        )
        if package_instance.uuid != retrieved_package_instance.uuid:
            # The package name got changed in the request.
            # Delete retrieved_package_instance.
            # Package_instance is either new, or it is an existing Package
            # instance if the name got changed to an already-existing one.
            retrieved_package_instance.versions.all().delete()
            retrieved_package_instance.delete()

        # remove all the existing versions
        package_instance.versions.all().delete()
        # replace them
        for version in versions:
            version = version["version"]
            PackageVer.objects.get_or_create(
                version=version,
                package=package_instance,
            )

        # NOTE: Bugzilla sync needs to have the equivalent of these 2 lines from
        #       BugzillaBareSyncMixinSerializer.update() executed before the return:
        #           bzkey = self._BugzillaBareSyncMixinSerializer__get_bz_api_key()
        #           package_instance.save(bz_api_key=bzkey)
        #       This is ensured by the MRO of
        #       FlawPackageVersionSerializer.update() and the following line:
        try:
            package_instance = super().update(package_instance)
        # TODO remove explicit 400 in favor of implicit 409
        # however it is not completely straight forward here
        # as it seems to break atomicity which is not acceptable
        except DataInconsistencyException as e:
            # translate internal exception into Django serializable
            raise BadRequest(
                "Received model contains non-refreshed and outdated data! "
                "It has been probably edited by someone else in the meantime"
            ) from e

        return package_instance


class FlawPackageVersionSerializer(
    ACLMixinSerializer,
    FlawPackageVersionSerializerMixin,
    BugzillaBareSyncMixinSerializer,
    IncludeExcludeFieldsMixin,
    TrackingMixinSerializer,
):
    """Package model serializer"""

    versions = FlawVersionSerializer(many=True)

    class Meta:
        model = Package
        fields = (
            ["package", "versions", "flaw", "uuid"]
            + ACLMixinSerializer.Meta.fields
            + TrackingMixinSerializer.Meta.fields
        )


@extend_schema_serializer(exclude_fields=["flaw"])
class FlawPackageVersionPutSerializer(FlawPackageVersionSerializer):
    # Extra serializer for PUT request because flaw shouldn't be
    # required in the body (already included in the path).
    pass


@extend_schema_serializer(exclude_fields=["flaw", "updated_dt"])
class FlawPackageVersionPostSerializer(FlawPackageVersionSerializer):
    # Extra serializer for POST request as there is no last update
    # timestamp but we need to make the field mandatory otherwise.
    # Flaw shouldn't be required in the body (already included in the path).
    pass


class FlawReferenceSerializer(
    ACLMixinSerializer,
    BugzillaSyncMixinSerializer,
    IncludeExcludeFieldsMixin,
    IncludeMetaAttrMixin,
    TrackingMixinSerializer,
):
    """FlawReference serializer"""

    class Meta:
        """filter fields"""

        model = FlawReference
        fields = (
            ["description", "flaw", "type", "url", "uuid"]
            + ACLMixinSerializer.Meta.fields
            + TrackingMixinSerializer.Meta.fields
        )


@extend_schema_serializer(exclude_fields=["updated_dt", "flaw"])
class FlawReferencePostSerializer(FlawReferenceSerializer):
    # extra serializer for POST request as there is no last update
    # timestamp but we need to make the field mandatory otherwise
    pass


@extend_schema_serializer(exclude_fields=["flaw"])
class FlawReferencePutSerializer(FlawReferenceSerializer):
    # Extra serializer for PUT request because flaw shouldn't be
    # required in the body (already included in the path).
    pass


class FlawCVSSSerializer(
    ACLMixinSerializer,
    BugzillaSyncMixinSerializer,
    IncludeExcludeFieldsMixin,
    TrackingMixinSerializer,
):
    """FlawCVSS serializer"""

    cvss_version = serializers.CharField(source="version")

    class Meta:
        """filter fields"""

        model = FlawCVSS
        fields = (
            ["comment", "cvss_version", "flaw", "issuer", "score", "uuid", "vector"]
            + ACLMixinSerializer.Meta.fields
            + TrackingMixinSerializer.Meta.fields
        )


@extend_schema_serializer(exclude_fields=["updated_dt", "flaw"])
class FlawCVSSPostSerializer(FlawCVSSSerializer):
    # Extra serializer for POST request as there is no last update
    # timestamp but we need to make the field mandatory otherwise.
    # Flaw shouldn't be required in the body (already included in the path).
    pass


@extend_schema_serializer(exclude_fields=["flaw"])
class FlawCVSSPutSerializer(FlawCVSSSerializer):
    # Extra serializer for PUT request because flaw shouldn't be
    # required in the body (already included in the path).
    pass


@extend_schema_serializer(
    deprecate_fields=[
        "state",
        "resolution",
        "is_major_incident",
        "cvss2",
        "cvss2_score",
        "cvss3",
        "cvss3_score",
        "nvd_cvss2",
        "nvd_cvss3",
    ]
)
class FlawSerializer(
    ACLMixinSerializer,
    JiraTaskSyncMixinSerializer,
    BugzillaSyncMixinSerializer,
    TrackingMixinSerializer,
    WorkflowModelSerializer,
    IncludeExcludeFieldsMixin,
    IncludeMetaAttrMixin,
):
    """serialize flaw model"""

    # All currently used keys in Flaw.meta_attr used for SwaggerUI population,
    # whenever we introduce new key, which users might be interested in, we should
    # add it to this tuple.
    #
    # See osidb/helpers.py::get_unique_meta_attr_keys for listing all existing keys
    # in the DB
    META_ATTR_KEYS = (
        "acknowledgments",
        "acks_not_needed",
        "affects",
        "alias",
        "bz_datascore",
        "bz_id",
        "checklists",
        "classification",
        "cvss2",
        "cvss2_score",
        "cvss2_vector",
        "cvss3",
        "cvss3_comment",
        "cvss3_score",
        "cvss3_vector",
        "cwe",
        "depends_on",
        "impact",
        "jira_trackers",
        "mitigate",
        "mitigation",
        "public",
        "references",
        "related_cves",
        "reported",
        "resolution",
        "source",
        "state",
        "statement",
        "task_owner",
        # Internal data
        # "acl_labels",
        # "bz_trace",
        # "bzimport_last_imported_dt",
        # "bzimport_last_job_uuid",
        # "bzimport_last_jobitem_id",
        # "bzimport_tracker_dict",
    )

    cve_id = serializers.CharField(required=False, allow_null=True)
    trackers = FlawAffectsTrackersField(source="*", read_only=True)
    affects = serializers.SerializerMethodField()
    comments = CommentSerializer(many=True, read_only=True)
    acknowledgments = FlawAcknowledgmentSerializer(many=True, read_only=True)
    references = FlawReferenceSerializer(many=True, read_only=True)
    cvss_scores = FlawCVSSSerializer(many=True, read_only=True)
    package_versions = PackageSerializer(many=True, read_only=True)

    meta = serializers.SerializerMethodField()
    meta_attr = serializers.SerializerMethodField()

    # This line forces the deprecated "is_major_incident" field NOT to change
    # from boolean to string. Otherwise, some unknown logic turns it into string.
    is_major_incident = serializers.BooleanField(required=False)

    @extend_schema_field(
        {
            "type": "object",
            "properties": {key: {"type": "string"} for key in META_ATTR_KEYS},
        }
    )
    def get_meta_attr(self, obj):
        return super().get_meta_attr(obj)

    @extend_schema_field(AffectSerializer(many=True))
    def get_affects(self, obj):
        """affects serializer getter"""
        affects = obj.affects.all()

        context = {
            "include_fields": self._next_level_include_fields.get("affects", []),
            "exclude_fields": self._next_level_exclude_fields.get("affects", []),
            "include_meta_attr": self._next_level_include_meta_attr.get("affects", []),
        }

        request = self.context.get("request")
        if request:

            # Filter only affects with trackers corresponding to specified IDs
            tracker_ids = request.query_params.get("tracker_ids")
            if tracker_ids:
                affects = affects.filter(
                    trackers__external_system_id__in=tracker_ids.split(",")
                )

        serializer = AffectSerializer(instance=affects, many=True, context=context)
        return serializer.data

    @extend_schema_field(MetaSerializer(many=True))
    def get_meta(self, obj):
        """Returns all meta information for a given flaw"""
        meta = obj.meta.all()
        request = self.context.get("request")
        if request:
            flaw_meta_type = request.query_params.get("flaw_meta_type")
            if flaw_meta_type is not None:
                flaw_meta_types = set(flaw_meta_type.split(","))
                flaw_meta_types = [
                    meta_type.upper() for meta_type in list(flaw_meta_types)
                ]
                meta = meta.filter(type__in=flaw_meta_types)
        serializer = MetaSerializer(instance=meta, many=True)
        return serializer.data

    class Meta:
        """filter fields"""

        model = Flaw
        fields = (
            [
                "uuid",
                "type",
                "cve_id",
                "state",
                "resolution",
                "impact",
                "component",
                "title",
                "trackers",
                "description",
                "summary",
                "requires_summary",
                "statement",
                "cwe_id",
                "unembargo_dt",
                "source",
                "reported_dt",
                "mitigation",
                "cvss2",
                "cvss2_score",
                "nvd_cvss2",
                "cvss3",
                "cvss3_score",
                "nvd_cvss3",
                "is_major_incident",
                "major_incident_state",
                "nist_cvss_validation",
                "affects",
                "meta",
                "comments",
                "meta_attr",
                "package_versions",
                "acknowledgments",
                "references",
                "cvss_scores",
            ]
            + ACLMixinSerializer.Meta.fields
            + TrackingMixinSerializer.Meta.fields
            + WorkflowModelSerializer.Meta.fields
        )


@extend_schema_serializer(exclude_fields=["updated_dt"])
class FlawPostSerializer(FlawSerializer):
    # extra serializer for POST request as there is no last update
    # timestamp but we need to make the field mandatory otherwise
    pass


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = [
            "bz_user_id",
            "jira_user_id",
        ]


class UserSerializer(serializers.ModelSerializer):
    groups = serializers.StringRelatedField(many=True)
    profile = ProfileSerializer(read_only=True)

    class Meta:
        model = User
        fields = [
            "username",
            "email",
            "groups",
            "profile",
        ]


class FlawCommentSerializer(
    CommentSerializer,
    ACLMixinSerializer,
    BugzillaSyncMixinSerializer,
    IncludeExcludeFieldsMixin,
    IncludeMetaAttrMixin,
):
    """FlawComment serializer for use by flaw_comments endpoint"""

    def create(self, validated_data):
        """
        Create FlawComment instance by deserializing input.

        Force empty external_system_id to force submitting and redownloading
        the new comment through bugzilla. Force sequential order so that the
        redownloaded comment continues to be the same instance (uuid).
        """

        flaw = validated_data["flaw"]
        next_order = 1
        if flaw.comments.exists():
            next_order = 1 + flaw.comments.aggregate(Max("order"))["order__max"]
        validated_data["order"] = next_order
        return super().create(validated_data)

    class Meta:
        """filter fields"""

        model = FlawComment
        fields = (
            [
                "flaw",
                "text",
            ]
            + CommentSerializer.Meta.fields
            + ACLMixinSerializer.Meta.fields
        )
        read_only_fields = [
            "external_system_id",
        ]


@extend_schema_serializer(
    exclude_fields=["external_system_id", "flaw", "order", "updated_dt"]
)
class FlawCommentPostSerializer(FlawCommentSerializer):
    # Extra serializer for POST request because some fields are not
    # submittable by the client and their submit values are hardwired
    # in create().
    # This class is just for schema generation, not for actual execution.
    pass
