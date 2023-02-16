"""
    serialize flaw model
"""

import logging
from collections import defaultdict
from typing import Dict, List, Tuple

from django.contrib.auth.models import User
from drf_spectacular.utils import extend_schema_field, extend_schema_serializer
from rest_framework import serializers

from apps.osim.serializers import WorkflowModelSerializer

from .mixins import TrackingMixin
from .models import (
    Affect,
    CVEv5PackageVersions,
    CVEv5Version,
    Erratum,
    Flaw,
    FlawComment,
    FlawMeta,
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


class TrackingMixinSerializer(serializers.ModelSerializer):
    """TrackingMixin class serializer"""

    created_dt = serializers.DateTimeField(read_only=True)
    updated_dt = serializers.DateTimeField(read_only=True)

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


class MetaSerializer(TrackingMixinSerializer):
    """FlawMeta serializer"""

    class Meta:
        """filter fields"""

        model = FlawMeta
        fields = [
            "uuid",
            "type",
            "meta_attr",
        ] + TrackingMixinSerializer.Meta.fields


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


class AffectSerializer(
    TrackingMixinSerializer, IncludeExcludeFieldsMixin, IncludeMetaAttrMixin
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
        # Internal data
        # "acl_labels",
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
        fields = [
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
        ] + TrackingMixinSerializer.Meta.fields


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


@extend_schema_serializer(deprecate_fields=["mitigated_by"])
class FlawSerializer(
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
        "source",
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
    package_versions = CVEv5PackageVersionsSerializer(many=True, read_only=True)
    embargoed = serializers.BooleanField(read_only=True)

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

    def create(self, validated_data):
        return Flaw.objects.create(**validated_data)

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
                "title",
                "trackers",
                "description",
                "summary",
                "statement",
                "cwe_id",
                "embargoed",
                "unembargo_dt",
                "source",
                "reported_dt",
                "mitigated_by",
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
            ]
            + TrackingMixinSerializer.Meta.fields
            + WorkflowModelSerializer.Meta.fields
        )


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
