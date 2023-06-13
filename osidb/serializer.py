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
from drf_spectacular.utils import extend_schema_field, extend_schema_serializer
from rest_framework import serializers

from apps.bbsync.mixins import BugzillaSyncMixin
from apps.osim.serializers import WorkflowModelSerializer

from .core import generate_acls
from .exceptions import DataInconsistencyException
from .helpers import ensure_list
from .mixins import ACLMixin, TrackingMixin
from .models import (
    Affect,
    CVEv5PackageVersions,
    CVEv5Version,
    Erratum,
    Flaw,
    FlawComment,
    FlawMeta,
    FlawReference,
    Profile,
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

    class Meta:
        """filter fields"""

        model = Erratum
        fields = [
            "et_id",
            "advisory_name",
        ] + TrackingMixinSerializer.Meta.fields


class TrackerSerializer(
    TrackingMixinSerializer,
    IncludeExcludeFieldsMixin,
    IncludeMetaAttrMixin,
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
        fields = [
            "uuid",
            "type",
            "external_system_id",
            "affects",
            "status",
            "resolution",
            "errata",
            "meta_attr",
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
    """FlawComment serializer"""

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


class BugzillaSyncMixinSerializer(serializers.ModelSerializer):
    """
    serializer mixin class implementing special handling of the models
    which need to perform Bugzilla sync as part of the save procedure
    """

    def __get_bz_api_key(self):
        bz_api_key = self.context["request"].META.get("HTTP_BUGZILLA_API_KEY")
        if not bz_api_key:
            raise serializers.ValidationError(
                {"Bugzilla-Api-Key": "This HTTP header is required."}
            )
        return bz_api_key

    def create(self, validated_data):
        """
        perform the ordinary instance create
        with providing BZ API key while saving
        """
        # NOTE: This won't work for many-to-many fields as
        # some logic from original .create() was overwritten

        instance = self.Meta.model(**validated_data)
        instance.save(bz_api_key=self.__get_bz_api_key())
        return instance

    def update(self, instance, validated_data):
        """
        perform the ordinary instance update
        with providing BZ API key while saving
        """
        # NOTE: This won't work for many-to-many fields as
        # some logic from original .create() was overwritten

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        try:
            instance.save(bz_api_key=self.__get_bz_api_key())
        except DataInconsistencyException as e:
            # translate internal exception into Django serializable
            raise BadRequest(
                "Received model contains non-refreshed and outdated data! "
                "It has been probably edited by someone else in the meantime"
            ) from e

        return instance

    class Meta:
        model = BugzillaSyncMixin
        abstract = True


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
            ]
            + ACLMixinSerializer.Meta.fields
            + TrackingMixinSerializer.Meta.fields
        )


@extend_schema_serializer(exclude_fields=["updated_dt"])
class AffectPostSerializer(AffectSerializer):
    # extra serializer for POST request as there is no last update
    # timestamp but we need to make the field mandatory otherwise
    pass


class CVEv5VersionsSerializer(serializers.ModelSerializer):
    """CVEv5 Package Version Serializer"""

    class Meta:
        model = CVEv5Version
        fields = ["version", "status"]


class CVEv5PackageVersionsSerializer(serializers.ModelSerializer):
    """CVEv5 package versions serializer"""

    versions = CVEv5VersionsSerializer(many=True)

    class Meta:
        model = CVEv5PackageVersions
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


class FlawReferenceSerializer(
    ACLMixinSerializer,
    BugzillaSyncMixinSerializer,
    IncludeExcludeFieldsMixin,
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


@extend_schema_serializer(exclude_fields=["updated_dt"])
class FlawReferencePostSerializer(FlawReferenceSerializer):
    # extra serializer for POST request as there is no last update
    # timestamp but we need to make the field mandatory otherwise
    pass


@extend_schema_serializer(deprecate_fields=["state", "resolution"])
class FlawSerializer(
    ACLMixinSerializer,
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
    references = FlawReferenceSerializer(many=True, read_only=True)
    package_versions = CVEv5PackageVersionsSerializer(many=True, read_only=True)

    meta = serializers.SerializerMethodField()
    meta_attr = serializers.SerializerMethodField()

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
                "affects",
                "meta",
                "comments",
                "meta_attr",
                "package_versions",
                "references",
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
