"""
    serialize flaw model
"""

import copy
import logging
import uuid
from collections import defaultdict
from distutils.util import strtobool
from typing import Dict, List, Tuple

import pghistory
from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import BadRequest
from django.db.models import Max
from django.utils import timezone
from drf_spectacular.utils import extend_schema_field, extend_schema_serializer
from pghistory.models import Events
from rest_framework import serializers

from apps.bbsync.mixins import BugzillaSyncMixin
from apps.taskman.constants import JIRA_TASKMAN_AUTO_SYNC_FLAW, SYNC_REQUIRED_FIELDS
from apps.taskman.mixins import JiraTaskSyncMixin
from apps.workflows.serializers import WorkflowModelSerializer

from .core import generate_acls
from .exceptions import DataInconsistencyException
from .helpers import differ, ensure_list
from .mixins import ACLMixin, Alert, AlertMixin, TrackingMixin
from .models import (
    CVSS,
    Affect,
    AffectCVSS,
    Erratum,
    Flaw,
    FlawAcknowledgment,
    FlawComment,
    FlawCVSS,
    FlawReference,
    Impact,
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

        self._include_meta_attr = []
        self._next_level_include_meta_attr = {}

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


class SyncToBzBulkEnablementMixinSerializer(serializers.ModelSerializer):
    """
    Provides parameter "sync_to_bz" that when set to False disables sync
    with Bugzilla for the given request. This is to be used by clients
    during bulk actions that are carried out by repeated single-instance
    calls (e.g. creating Trackers). The reason is that the final flaw bz
    sync that happens after e.g. creating a tracker can take minutes for
    huge flaws.

    The parameter does nothing if BZ sync is not enabled in the OSIDB instance.
    """

    sync_to_bz = serializers.BooleanField(
        required=False,
        write_only=True,
        help_text=(
            "Setting sync_to_bz to false disables flaw sync with Bugzilla "
            "after this operation. Use only as part of bulk actions and "
            "trigger a flaw bugzilla sync afterwards. Does nothing if BZ "
            "is disabled."
        ),
    )

    class Meta:
        fields = ["sync_to_bz"]
        abstract = True

    # Not named exactly as the write-only field to prevent Django
    # from trying to treat it as a readable field.
    @property
    def sync_to_bz_helper(self):
        return getattr(self, "_sync_to_bz", True)

    def is_valid(self, raise_exception=False):
        ret = super().is_valid(raise_exception=raise_exception)
        # By default, sync with bz is not disabled.
        # sync_to_bz: false is a special case for bulk actions.
        # This can be removed after decommissioning bugzilla.
        self._sync_to_bz = self._validated_data.pop("sync_to_bz", True)
        return ret


class ErratumSerializer(
    IncludeExcludeFieldsMixin,
    TrackingMixinSerializer,
):
    """Erratum serializer"""

    et_id = serializers.IntegerField(read_only=True)
    advisory_name = serializers.CharField(read_only=True)
    shipped_dt = serializers.DateTimeField(read_only=True, allow_null=True)

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
        # Already validated in EmbargoedField for non-bulk requests
        try:
            # For usual dict-typed requests with one object per request.
            embargoed = self.context["request"].data.get("embargoed")
        except AttributeError:
            # For bulk list-typed requests with multiple objects per request.
            embargoed_values = [
                d.get("embargoed") for d in self.context["request"].data
            ]
            if not embargoed_values:
                raise serializers.ValidationError(
                    {
                        "embargoed": "No value provided. All objects in a bulk request must have the (same) value for embargoed."
                    }
                )
            embargoed_values_dedup = tuple(set(embargoed_values))
            if len(embargoed_values_dedup) > 1 or len(embargoed_values) != len(
                self.context["request"].data
            ):
                # Even if boolean-equivalent values are provided, still require an identical value.
                raise serializers.ValidationError(
                    {
                        "embargoed": "Different values provided in a bulk request. All objects in a bulk request must have the same value for embargoed."
                    }
                )
            embargoed = embargoed_values_dedup[0]

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


class AlertSerializer(serializers.ModelSerializer):
    """Alerts indicate some inconsistency in a linked flaw, affect, tracker or other models."""

    parent_uuid = serializers.SerializerMethodField()
    parent_model = serializers.SerializerMethodField()

    class Meta:
        model = Alert
        fields = [
            "uuid",
            "name",
            "description",
            "alert_type",
            "resolution_steps",
            "parent_uuid",
            "parent_model",
        ]

    def get_parent_uuid(self, obj):
        return obj.object_id

    def get_parent_model(self, obj):
        return obj.content_type.model


class AlertMixinSerializer(serializers.ModelSerializer):
    """Serializes the alerts in models that implement AlertMixin."""

    alerts = AlertSerializer(many=True, read_only=True)

    class Meta:
        model = AlertMixin
        abstract = True
        fields = ["alerts"]


class AuditSerializer(serializers.ModelSerializer):

    pgh_data = serializers.SerializerMethodField()

    def get_pgh_data(self, obj):
        # remove acls from entity snapshot
        data = obj.pgh_data
        data.pop("acl_read")
        data.pop("acl_write")
        return obj.pgh_data

    class Meta:
        model = Events
        fields = [
            "pgh_created_at",
            "pgh_slug",
            "pgh_obj_model",
            "pgh_obj_id",
            "pgh_label",
            "pgh_context",
            "pgh_diff",
            "pgh_data",
        ]


class HistoricalEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Events
        fields = [
            "pgh_created_at",
            "pgh_slug",
            "pgh_label",
            "pgh_context",
            "pgh_diff",
        ]


class HistoryMixinSerializer(serializers.ModelSerializer):

    history = serializers.SerializerMethodField()

    def __init__(self, *args, **kwargs):
        # Instantiate the superclass normally
        super().__init__(*args, **kwargs)

        request = self.context.get("request")
        include_history_param = None
        # Get include history from request
        if request:
            include_history_param = request.query_params.get("include_history")
        else:
            include_history_param = self.context.get("include_history")

        if include_history_param is None:
            self.fields.pop("history", None)

    @extend_schema_field(HistoricalEventSerializer(many=True, read_only=True))
    def get_history(self, obj):
        """history events serializer getter"""
        history = pghistory.models.Events.objects.tracks(obj)
        serializer = HistoricalEventSerializer(
            instance=history, many=True, read_only=True
        )
        return serializer.data

    class Meta:
        """filter fields"""

        model = Events
        abstract = True
        fields = ["history"]


class TrackerSerializer(
    ACLMixinSerializer,
    AlertMixinSerializer,
    BugzillaAPIKeyMixin,
    IncludeExcludeFieldsMixin,
    IncludeMetaAttrMixin,
    JiraAPIKeyMixin,
    TrackingMixinSerializer,
    SyncToBzBulkEnablementMixinSerializer,
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
            + AlertMixinSerializer.Meta.fields
            + TrackingMixinSerializer.Meta.fields
            + SyncToBzBulkEnablementMixinSerializer.Meta.fields
        )
        read_only_fields = [
            "external_system_id",
            "status",
            "type",
            "resolution",
        ]

    def create(self, validated_data):
        """
        perform the tracker instance creation
        """
        ############################
        # 1) prepare prerequisites #
        ############################

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
        tracker = self.Meta.model(**validated_data)

        #########################
        # 2) pre-create actions #
        #########################

        # create new tracker instance in the local DB first
        # so we can create the links before the backend sync

        # Alerts will be created after links and timestamps are
        # generated by BTS and will be fixed during synchronization
        TIMEZONE = timezone.get_current_timezone()
        tracker.created_dt = timezone.datetime(1970, 1, 1, tzinfo=TIMEZONE)
        tracker.updated_dt = timezone.datetime(1970, 1, 1, tzinfo=TIMEZONE)
        tracker.save(no_alerts=True, auto_timestamps=False)
        # create affect-tracker links
        for affect in affects:
            tracker.affects.add(affect)

        #####################
        # 3) create actions #
        #####################
        tracker.save(
            # the serializer does not care for the backend system
            # therefore at this point we simply require both secrets
            bz_api_key=self.get_bz_api_key(),
            jira_token=self.get_jira_token(),
        )

        ##########################
        # 4) post-create actions #
        ##########################

        if self.sync_to_bz_helper:
            # related flaws need to be saved to Bugzilla in order to update SRT notes with the new
            # Jira tracker ID (Bugzilla trackers are linked naturally through Bugzilla relations)
            if tracker.type == Tracker.TrackerType.JIRA:
                for affect in affects:
                    # do not raise validation errors here as the flaw is not what the user touches
                    # which would make the errors hard to understand and cause the tracker to orphan
                    affect.flaw.save(
                        bz_api_key=self.get_bz_api_key(),
                        no_alerts=True,
                        raise_validation_error=False,
                    )
        else:
            # Special path for bulk tracker create. Works for Jira trackers only.
            # Do not sync with BZ, as that can take a long time for large flaws.
            pass

        #####################
        # 5) return created #
        #####################

        return tracker

    def update(self, tracker, validated_data):
        """
        perform the tracker instance update
        """
        ############################
        # 1) prepare prerequisites #
        ############################

        # transform the embargoed status to the ACLs
        validated_data = ACLMixinSerializer.embargoed2acls(self, validated_data)

        #########################
        # 2) pre-update actions #
        #########################

        affects = set(tracker.affects.all())
        # update the relations by simply recreating them
        # which will both delete the old and add the new
        tracker.affects.clear()
        for affect in validated_data.pop("affects", []):
            tracker.affects.add(affect)

        #####################
        # 3) update actions #
        #####################

        # update the attributes
        for attr, value in validated_data.items():
            setattr(tracker, attr, value)

        tracker.save(
            bz_api_key=self.get_bz_api_key(),
            jira_token=self.get_jira_token(),
            auto_timestamps=False,
        )

        ##########################
        # 4) post-update actions #
        ##########################

        # related flaws need to be saved to Bugzilla in order to update
        # SRT notes with both added and removed Jira tracker IDs
        # (Bugzilla trackers are linked naturally through Bugzilla relations)
        if tracker.type == Tracker.TrackerType.JIRA:
            # iterate over both added and removed affects
            for affect in affects ^ set(tracker.affects.all()):
                # do not raise validation errors here as the flaw is not what the user touches
                # which would make the errors hard to understand and cause the tracker to orphan
                affect.flaw.save(
                    bz_api_key=self.get_bz_api_key(),
                    no_alerts=True,
                    raise_validation_error=False,
                )

        #####################
        # 5) return updated #
        #####################

        return tracker


@extend_schema_serializer(exclude_fields=["external_system_id"])
class TrackerPostSerializer(TrackerSerializer):
    # extra serializer for POST request to exclude
    # not yet existing but otherwise mandatory fields
    pass


class CommentSerializer(AlertMixinSerializer, TrackingMixinSerializer):
    """FlawComment serializer for use by FlawSerializer"""

    class Meta:
        """filter fields"""

        model = FlawComment
        fields = (
            [
                "uuid",
                "text",
                "external_system_id",
                "order",
                "creator",
                "is_private",
            ]
            + AlertMixinSerializer.Meta.fields
            + TrackingMixinSerializer.Meta.fields
        )


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


class BugzillaSyncMixinSerializer(BugzillaAPIKeyMixin, serializers.ModelSerializer):
    """
    serializer mixin class implementing special handling of the models
    which need to perform Bugzilla sync as part of the save procedure
    """

    def create(self, validated_data):
        """
        perform the ordinary instance create
        with providing BZ API key while saving
        """
        skip_bz_sync = validated_data.pop("skip_bz_sync", False)

        instance = super().create(validated_data)
        if not skip_bz_sync:
            instance.bzsync(bz_api_key=self.get_bz_api_key())
        return instance

    def update(self, instance, validated_data):
        """
        perform the ordinary instance update
        with providing BZ API key while saving
        """
        skip_bz_sync = validated_data.pop("skip_bz_sync", False)

        if not skip_bz_sync:
            # bzsync of flaw depends on comparing it with the old instance, but the instance is updated in
            # the update call through the JiraTaskSyncMixinSerializer and it is lost.
            kwargs = {}
            if isinstance(instance, Flaw):
                kwargs["old_instance"] = copy.deepcopy(instance)

        instance = super().update(instance, validated_data)
        if not skip_bz_sync:
            instance.bzsync(bz_api_key=self.get_bz_api_key(), **kwargs)
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


class AbstractCVSSSerializer(
    ACLMixinSerializer,
    AlertMixinSerializer,
    BugzillaSyncMixinSerializer,
    IncludeExcludeFieldsMixin,
    TrackingMixinSerializer,
):
    """Abstract serializer for FlawCVSS and AffectCVSS serializer"""

    cvss_version = serializers.ChoiceField(choices=CVSS.CVSSVersion, source="version")
    score = serializers.FloatField(read_only=True)
    comment = serializers.CharField(required=False, allow_null=True, allow_blank=True)

    class Meta:
        abstract = True
        fields = (
            # Also add "affect" or "flaw" for AffectCVSS or FlawCVSS
            ["comment", "cvss_version", "issuer", "score", "uuid", "vector"]
            + ACLMixinSerializer.Meta.fields
            + AlertMixinSerializer.Meta.fields
            + TrackingMixinSerializer.Meta.fields
        )


class AffectCVSSSerializer(
    AbstractCVSSSerializer,
):
    """AffectCVSS serializer"""

    cvss_version = serializers.ChoiceField(
        choices=AffectCVSS.CVSSVersion, source="version"
    )

    class Meta:
        """filter fields"""

        model = AffectCVSS
        fields = ["affect"] + AbstractCVSSSerializer.Meta.fields


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


class AffectSerializer(
    ACLMixinSerializer,
    AlertMixinSerializer,
    BugzillaSyncMixinSerializer,
    TrackingMixinSerializer,
    IncludeExcludeFieldsMixin,
    IncludeMetaAttrMixin,
    JiraAPIKeyMixin,
    HistoryMixinSerializer,
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
        "impact",
        "module_name",
        "module_stream",
        "ps_component",
        "ps_module",
        "ps_product",
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
            instance=obj.trackers.all(), many=True, read_only=True, context=context
        )
        return serializer.data

    class Meta:
        """filter fields"""

        model = Affect
        fields = (
            [
                "uuid",
                "flaw",
                "affectedness",
                "resolution",
                "ps_module",
                "ps_product",
                "ps_component",
                "impact",
                "trackers",
                "meta_attr",
                "delegated_resolution",
                "cvss_scores",
            ]
            + ACLMixinSerializer.Meta.fields
            + AlertMixinSerializer.Meta.fields
            + TrackingMixinSerializer.Meta.fields
            + HistoryMixinSerializer.Meta.fields
        )

    def update(self, new_affect, validated_data):
        """
        perform the affect instance update
        with any necessary extra actions
        """
        #########################
        # 1) pre-update actions #
        #########################

        # store the old affect for the later comparison
        old_affect = Affect.objects.get(uuid=new_affect.uuid)

        #####################
        # 2) update actions #
        #####################

        # perform regular affect update
        new_affect = super().update(new_affect, validated_data)

        ##########################
        # 3) post-update actions #
        ##########################

        # update trackers if needed
        self.update_trackers(old_affect, new_affect)

        #####################
        # 4) return updated #
        #####################

        return new_affect

    def update_trackers(self, old_affect, new_affect):
        """
        update the related trackers if needed
        """
        # no tracker updates for community affects
        # because it was requested not to spam them
        if old_affect.is_community:
            return

        promote = False
        # we only need to sync the trackers when crucial attributes change
        # plus in the case of the impact we only care for the increase
        #
        # in the case of PS module we cannot auto-adjust the trackers
        # since we simply cannot guess which PS update stream is correct
        #
        # in the case of impact we should ideally check whether the increase actually
        # increases the tracker aggregated impact (in cases of multi-flaw trackers)
        # but that drastically increases the code complexity and brings only a little
        # value - would prevent a rare extra update attempt without any real effect
        if not differ(old_affect, new_affect, ["flaw", "ps_component"]) and Impact(
            old_affect.impact
        ) >= Impact(new_affect.impact):
            # regenerate trackers on affect promotion from NEW to
            # other value to remove the validation-requested label
            if not (
                old_affect.affectedness
                == Affect.AffectAffectedness.NEW
                != new_affect.affectedness
            ):
                return

            promote = True  # remember to only regenarate Jira trackers

        for tracker in new_affect.trackers.all():
            # no tracker updates for the closed ones
            # because we consider these already done
            if tracker.is_closed:
                continue

            # only Jira trackers are regenerated on affect promotion
            if promote and tracker.type != Tracker.TrackerType.JIRA:
                continue

            # perform the tracker update
            # could be done async eventually
            tracker.save(
                # the serializer does not care for the backend system
                # therefore at this point we simply require both secrets
                bz_api_key=self.get_bz_api_key(),
                jira_token=self.get_jira_token(),
                # do not raise validation errors here as the tracker is not what
                # the user touches which would make the errors hard to understand
                raise_validation_error=False,
            )


@extend_schema_serializer(exclude_fields=["updated_dt"])
class AffectPostSerializer(AffectSerializer):
    # extra serializer for POST request as there is no last update
    # timestamp but we need to make the field mandatory otherwise
    pass


@extend_schema_serializer()
class AffectBulkPutSerializer(AffectSerializer):
    # extra serializer for a single instance within a bulk PUT request
    # as it needs UUID to be a part of each Affect's object.
    META_ATTR_KEYS = tuple(AffectSerializer.META_ATTR_KEYS + ("uuid",))
    uuid = serializers.UUIDField(
        required=True,
    )

    class Meta:
        model = Affect
        fields = AffectSerializer.Meta.fields + ["uuid"]


class AffectBulkPostPutResponseSerializer(serializers.ModelSerializer):
    # Extra serializer for drf-spectacular to describe format of bulk POST & PUT response.
    results = AffectSerializer(many=True)

    class Meta:
        model = Affect
        fields = ["results"]


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


class PackageSerializer(AlertMixinSerializer):
    """package_versions (Package model) serializer for read-only use in FlawSerializer."""

    versions = PackageVerSerializer(many=True)

    class Meta:
        model = Package
        fields = ["package", "versions"] + AlertMixinSerializer.Meta.fields


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
    AlertMixinSerializer,
    BugzillaSyncMixinSerializer,
    IncludeExcludeFieldsMixin,
    TrackingMixinSerializer,
):
    """FlawAcknowledgment serializer"""

    class Meta:
        """filter fields"""

        model = FlawAcknowledgment
        fields = (
            ["name", "affiliation", "from_upstream", "flaw", "uuid"]
            + ACLMixinSerializer.Meta.fields
            + AlertMixinSerializer.Meta.fields
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
    AlertMixinSerializer,
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
            + AlertMixinSerializer.Meta.fields
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
    AbstractCVSSSerializer,
):
    """FlawCVSS serializer"""

    cvss_version = serializers.ChoiceField(
        choices=FlawCVSS.CVSSVersion, source="version"
    )

    class Meta:
        """filter fields"""

        model = FlawCVSS
        fields = ["flaw"] + AbstractCVSSSerializer.Meta.fields


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


class FlawSerializer(
    ACLMixinSerializer,
    BugzillaSyncMixinSerializer,
    JiraTaskSyncMixinSerializer,
    TrackingMixinSerializer,
    WorkflowModelSerializer,
    IncludeExcludeFieldsMixin,
    IncludeMetaAttrMixin,
    JiraAPIKeyMixin,
    AlertMixinSerializer,
    HistoryMixinSerializer,
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
        "source",
        "statement",
        "task_owner",
    )

    cve_id = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    trackers = FlawAffectsTrackersField(source="*", read_only=True)
    affects = serializers.SerializerMethodField()
    comments = CommentSerializer(many=True, read_only=True)
    acknowledgments = FlawAcknowledgmentSerializer(many=True, read_only=True)
    references = FlawReferenceSerializer(many=True, read_only=True)
    cvss_scores = FlawCVSSSerializer(many=True, read_only=True)
    package_versions = PackageSerializer(many=True, read_only=True)

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

            # If we have requested history on Flaw, then apply it to affects as well
            include_history = request.query_params.get("include_history")
            if include_history:
                context["include_history"] = include_history

        serializer = AffectSerializer(
            instance=affects, many=True, read_only=True, context=context
        )
        return serializer.data

    class Meta:
        """filter fields"""

        model = Flaw
        fields = (
            [
                "uuid",
                "cve_id",
                "impact",
                "components",
                "title",
                "trackers",
                "comment_zero",
                "cve_description",
                "requires_cve_description",
                "statement",
                "cwe_id",
                "unembargo_dt",
                "source",
                "reported_dt",
                "mitigation",
                "major_incident_state",
                "major_incident_start_dt",
                "nist_cvss_validation",
                "affects",
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
            + AlertMixinSerializer.Meta.fields
            + HistoryMixinSerializer.Meta.fields
        )

    def _is_public(self, flaw, validated_data):
        """
        check whether the flaw is public
        based on the preliminary raw ACLs
        """
        return all(
            group in flaw.acls_public
            # the read groups need to be gathered from validated data
            for group in self.embargoed2acls(validated_data)["acl_read"]
        )

    def update(self, new_flaw, validated_data):
        """
        perform the flaw instance update
        with any necessary extra actions
        """
        #########################
        # 1) pre-update actions #
        #########################

        # store the old flaw for the later comparison
        old_flaw = Flaw.objects.get(uuid=new_flaw.uuid)

        #####################
        # 2) update actions #
        #####################

        # unembargo
        #
        # the only possible change of the embargo visibility is
        # the unembargo as the validations prevent the opposite
        #
        # we have to check whether the new flaw is public
        # based on the raw ACLs as it was not yet updated
        if old_flaw.is_embargoed and self._is_public(new_flaw, validated_data):
            new_flaw.unembargo()

        # perform regular flaw update
        new_flaw = super().update(new_flaw, validated_data)

        # Force Jira task creation if requested
        request = self.context.get("request")
        if request:
            create_jira_task = request.query_params.get("create_jira_task")
            if create_jira_task:
                new_flaw.tasksync(jira_token=self.get_jira_token(), force_creation=True)

        ##########################
        # 3) post-update actions #
        ##########################

        # update trackers if needed
        self.update_trackers(old_flaw, new_flaw)

        #####################
        # 4) return updated #
        #####################

        return new_flaw

    def update_trackers(self, old_flaw, new_flaw):
        """
        update the related trackers if needed
        """

        def mi_differ(flaw1, flaw2):
            """
            boolean check whether the given flaws
            differ in MI value in an important way
            """
            if not differ(flaw1, flaw2, ["major_incident_state"]):
                return False

            # we only care for a change from or to some of the approved states
            return bool(
                {flaw1.major_incident_state, flaw2.major_incident_state}.intersection(
                    [
                        Flaw.FlawMajorIncident.APPROVED,
                        Flaw.FlawMajorIncident.CISA_APPROVED,
                    ]
                )
            )

        # we only need to sync the trackers when crucial attributes change
        # plus in the case of the impact we only care for the increase
        # plus in the case of the MI we care for specific changes only
        #
        # the crucial attributes are those influencing the SLA deadline plus the CVE ID
        #
        # in the case of impact we should ideally check whether the increase actually
        # increases the tracker aggregated impact (in cases of multi-flaw trackers)
        # but that drastically increases the code complexity and brings only a little
        # value - would prevent a rare extra update attempt without any real effect
        if (
            not differ(old_flaw, new_flaw, ["cve_id", "is_embargoed", "unembargo_dt"])
            and not mi_differ(old_flaw, new_flaw)
            and Impact(old_flaw.impact) >= Impact(new_flaw.impact)
        ):
            return

        for affect in new_flaw.affects.all():
            # no tracker updates for community affects
            # because it was requested not to spam them
            if affect.is_community:
                continue

            for tracker in affect.trackers.all():
                # no tracker updates for the closed ones
                # because we consider these already done
                if tracker.is_closed:
                    continue

                # perform the tracker update
                # could be done async eventually
                tracker.save(
                    # the serializer does not care for the backend system
                    # therefore at this point we simply require both secrets
                    bz_api_key=self.get_bz_api_key(),
                    jira_token=self.get_jira_token(),
                    # do not raise validation errors here as the tracker is not what
                    # the user touches which would make the errors hard to understand
                    raise_validation_error=False,
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
):
    """FlawComment serializer for use by flaw_comments endpoint"""

    def create(self, validated_data):
        """
        Create FlawComment instance by deserializing input.

        Force sequential order. This is required by bzimport. Also makes
        ordering exact.
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
