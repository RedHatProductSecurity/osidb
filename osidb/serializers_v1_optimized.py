from collections import defaultdict

from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from osidb.models import (
    Affect,
    AffectCVSS,
    AffectV1,
    CollaboratorLabel,
    Erratum,
    FlawAcknowledgment,
    FlawComment,
    FlawReference,
    Package,
    Tracker,
    UpstreamData,
)
from osidb.models.flaw.cvss import CVSS, FlawCVSS
from osidb.models.flaw.flaw import Flaw
from osidb.serializer import (
    ACLMixinSerializer,
    AffectCVSSSerializer,
    AlertMixinSerializer,
    CommentSerializer,
    ErratumSerializer,
    FlawAcknowledgmentSerializer,
    FlawCollaboratorSerializer,
    FlawCVSSSerializer,
    FlawReferenceSerializer,
    HistoryMixinSerializer,
    HistoryRelation,
    PackageSerializer,
    PackageVerSerializer,
    TrackingMixinSerializer,
    UpstreamDataSerializer,
    parse_fields,
)


def _serialize_prefetched(obj, relation, serializer_cls, context):
    return serializer_cls(
        instance=getattr(obj, relation).all(),
        many=True,
        read_only=True,
        context=context,
    ).data


class SimpleIncludeExcludeFieldsMixin:
    """Simplified field filtering mixin without ModelSerializer inheritance."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._next_level_include_fields = {}
        self._next_level_exclude_fields = {}

        request = self.context.get("request")

        if request:
            include_fields_param = request.query_params.get("include_fields")
            exclude_fields_param = request.query_params.get("exclude_fields")

            include_fields = (
                include_fields_param.split(",") if include_fields_param else []
            )
            exclude_fields = (
                exclude_fields_param.split(",") if exclude_fields_param else []
            )
        else:
            include_fields = self.context.get("include_fields", [])
            exclude_fields = self.context.get("exclude_fields", [])

        if include_fields:
            current_level, self._next_level_include_fields = parse_fields(
                include_fields
            )
            for field_name in list(self.fields.keys()):
                if (
                    field_name not in current_level
                    and f"{field_name}.*" not in current_level
                ):
                    if field_name not in self._next_level_include_fields:
                        self.fields.pop(field_name, None)

        if exclude_fields:
            current_level, self._next_level_exclude_fields = parse_fields(
                exclude_fields
            )
            for field_name in current_level:
                self.fields.pop(field_name, None)

    def _build_nested_context(self, field_name, extra=None):
        context = dict(extra or {})
        if hasattr(self, "_next_level_include_fields"):
            context["include_fields"] = self._next_level_include_fields.get(
                field_name, []
            )
        if hasattr(self, "_next_level_exclude_fields"):
            context["exclude_fields"] = self._next_level_exclude_fields.get(
                field_name, []
            )
        if hasattr(self, "_next_level_include_meta_attr"):
            context["include_meta_attr"] = self._next_level_include_meta_attr.get(
                field_name, []
            )
        if "history_cache" in self.context:
            context["history_cache"] = self.context["history_cache"]
        if "tracker_to_affects_map" in self.context:
            context["tracker_to_affects_map"] = self.context["tracker_to_affects_map"]
        request = self.context.get("request")
        if request and request.query_params.get("include_history"):
            context["include_history"] = request.query_params.get("include_history")
        return context


class SimpleIncludeMetaAttrMixin:
    """Simplified meta_attr filtering mixin without ModelSerializer inheritance."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._include_meta_attr = []
        self._next_level_include_meta_attr = {}

        request = self.context.get("request")

        if request:
            include_meta_attr_param = request.query_params.get("include_meta_attr")
            include_meta_attr = (
                include_meta_attr_param.split(",") if include_meta_attr_param else None
            )
        else:
            include_meta_attr = self.context.get("include_meta_attr")

        if include_meta_attr is not None:
            self._include_meta_attr, self._next_level_include_meta_attr = parse_fields(
                include_meta_attr
            )

        if not self._include_meta_attr:
            self.fields.pop("meta_attr", None)

    def get_meta_attr(self, obj):
        meta_attr = obj.meta_attr
        if "*" in self._include_meta_attr:
            return meta_attr
        else:
            return {
                key: value
                for key, value in meta_attr.items()
                if key in self._include_meta_attr
            }


def _make_cvss_serializer(model_cls, fields_source):
    class CVSSSerializer(
        ACLMixinSerializer,
        AlertMixinSerializer,
        TrackingMixinSerializer,
        serializers.ModelSerializer,
    ):
        cvss_version = serializers.CharField(source="version", read_only=True)
        issuer = serializers.ChoiceField(choices=CVSS.CVSSIssuer, read_only=True)

        class Meta:
            model = model_cls
            fields = fields_source

    return CVSSSerializer


FlawCVSSSerializerV1Optimized = _make_cvss_serializer(
    FlawCVSS, FlawCVSSSerializer.Meta.fields
)
AffectCVSSSerializerV1Optimized = _make_cvss_serializer(
    AffectCVSS, AffectCVSSSerializer.Meta.fields
)


class CommentSerializerV1Optimized(
    AlertMixinSerializer,
    TrackingMixinSerializer,
    serializers.ModelSerializer,
):
    class Meta:
        model = FlawComment
        fields = CommentSerializer.Meta.fields


class FlawAcknowledgmentSerializerV1Optimized(
    SimpleIncludeExcludeFieldsMixin,
    ACLMixinSerializer,
    AlertMixinSerializer,
    TrackingMixinSerializer,
    serializers.ModelSerializer,
):
    class Meta:
        model = FlawAcknowledgment
        fields = FlawAcknowledgmentSerializer.Meta.fields


class FlawReferenceSerializerV1Optimized(
    SimpleIncludeExcludeFieldsMixin,
    ACLMixinSerializer,
    AlertMixinSerializer,
    TrackingMixinSerializer,
    serializers.ModelSerializer,
):
    class Meta:
        model = FlawReference
        fields = FlawReferenceSerializer.Meta.fields


class PackageSerializerV1Optimized(AlertMixinSerializer):
    package = serializers.CharField(read_only=True)
    versions = PackageVerSerializer(many=True, read_only=True)

    class Meta:
        model = Package
        fields = PackageSerializer.Meta.fields


class UpstreamDataSerializerV1Optimized(
    SimpleIncludeExcludeFieldsMixin,
    ACLMixinSerializer,
    AlertMixinSerializer,
    TrackingMixinSerializer,
    serializers.ModelSerializer,
):
    class Meta:
        model = UpstreamData
        fields = UpstreamDataSerializer.Meta.fields


class FlawCollaboratorSerializerV1Optimized(TrackingMixinSerializer):
    flaw = serializers.UUIDField(source="flaw_id", read_only=True)
    label = serializers.CharField(source="name", read_only=True)
    type = serializers.CharField(read_only=True)

    class Meta:
        model = CollaboratorLabel
        fields = FlawCollaboratorSerializer.Meta.fields


class ErratumSerializerV1Optimized(
    TrackingMixinSerializer,
    serializers.ModelSerializer,
):
    class Meta:
        model = Erratum
        fields = ErratumSerializer.Meta.fields


class TrackerSerializerV1Optimized(
    SimpleIncludeExcludeFieldsMixin,
    SimpleIncludeMetaAttrMixin,
    ACLMixinSerializer,
    AlertMixinSerializer,
    TrackingMixinSerializer,
):
    affects = serializers.SerializerMethodField()
    meta_attr = serializers.SerializerMethodField()
    errata = serializers.SerializerMethodField()

    def get_affects(self, obj):
        tracker_to_affects_map = self.context.get("tracker_to_affects_map", {})
        return tracker_to_affects_map.get(str(obj.uuid), [])

    def get_errata(self, obj):
        return _serialize_prefetched(
            obj, "errata", ErratumSerializerV1Optimized, self.context
        )

    class Meta:
        model = Tracker
        fields = [
            "affects",
            "cve_id",
            "errata",
            "external_system_id",
            "meta_attr",
            "ps_update_stream",
            "status",
            "resolution",
            "not_affected_justification",
            "type",
            "uuid",
            "special_handling",
            "resolved_dt",
            "embargoed",
            "visibility",
            "alerts",
            "created_dt",
            "updated_dt",
        ]


class AffectSerializerV1Optimized(
    SimpleIncludeExcludeFieldsMixin,
    SimpleIncludeMetaAttrMixin,
    ACLMixinSerializer,
    AlertMixinSerializer,
    TrackingMixinSerializer,
    HistoryMixinSerializer,
):
    flaw = serializers.UUIDField(source="flaw_id", read_only=True)
    delegated_resolution = serializers.CharField(read_only=True)
    delegated_not_affected_justification = serializers.CharField(read_only=True)
    ps_product = serializers.CharField(read_only=True)
    meta_attr = serializers.SerializerMethodField()
    trackers = serializers.SerializerMethodField()
    cvss_scores = serializers.SerializerMethodField()

    def get_trackers(self, obj):
        if obj.tracker is None:
            return []
        return [
            TrackerSerializerV1Optimized(
                instance=obj.tracker,
                read_only=True,
                context=self._build_nested_context("trackers"),
            ).data
        ]

    def get_cvss_scores(self, obj):
        return _serialize_prefetched(
            obj, "cvss_scores", AffectCVSSSerializerV1Optimized, self.context
        )

    class Meta:
        model = Affect
        fields = [
            "uuid",
            "flaw",
            "affectedness",
            "resolution",
            "ps_module",
            "cve_id",
            "ps_product",
            "ps_component",
            "impact",
            "trackers",
            "meta_attr",
            "delegated_resolution",
            "cvss_scores",
            "purl",
            "not_affected_justification",
            "delegated_not_affected_justification",
            "resolved_dt",
            "embargoed",
            "visibility",
            "alerts",
            "created_dt",
            "updated_dt",
            "history",
        ]


class FlawSerializerV1Optimized(
    SimpleIncludeExcludeFieldsMixin,
    SimpleIncludeMetaAttrMixin,
    ACLMixinSerializer,
    AlertMixinSerializer,
    TrackingMixinSerializer,
    HistoryMixinSerializer,
):
    history_relations = (
        HistoryRelation(
            field_name="affects",
            serializer_class=AffectSerializerV1Optimized,
            accessor=lambda flaw: AffectV1.objects.filter(flaw=flaw),
        ),
    )

    selected_cve_description = serializers.ReadOnlyField()
    requires_cve_description = serializers.SerializerMethodField()
    trackers = serializers.SerializerMethodField()
    meta_attr = serializers.SerializerMethodField()
    aegis_meta = serializers.JSONField(read_only=True)
    affects = serializers.SerializerMethodField()
    comments = serializers.SerializerMethodField()
    acknowledgments = serializers.SerializerMethodField()
    references = serializers.SerializerMethodField()
    cvss_scores = serializers.SerializerMethodField()
    package_versions = serializers.SerializerMethodField()
    upstream_data = serializers.SerializerMethodField()
    labels = serializers.SerializerMethodField()

    classification = serializers.JSONField(read_only=True)
    group_key = serializers.CharField(read_only=True, allow_null=True)
    owner = serializers.CharField(read_only=True, allow_null=True)
    task_key = serializers.CharField(read_only=True, allow_null=True)
    team_id = serializers.CharField(read_only=True, allow_null=True)

    def get_requires_cve_description(self, obj):
        return obj.FlawRequiresCVEDescription.NOVALUE

    @extend_schema_field({"type": "array", "items": {"type": "string"}})
    def get_trackers(self, obj):
        return sorted(
            {
                affect.tracker.external_system_id
                for affect in obj.affects.all()
                if affect.tracker
            }
        )

    @extend_schema_field(AffectSerializerV1Optimized(many=True))
    def get_affects(self, obj):
        affects = list(obj.affects.all())

        request = self.context.get("request")
        if request:
            tracker_ids_param = request.query_params.get("tracker_ids")
            if tracker_ids_param:
                tracker_uuids = set(
                    Tracker.objects.filter(
                        external_system_id__in=tracker_ids_param.split(",")
                    ).values_list("uuid", flat=True)
                )
                affects = [a for a in affects if a.tracker_id in tracker_uuids]

        tracker_to_affects_map = defaultdict(list)
        for affect in affects:
            if affect.tracker_id:
                tracker_to_affects_map[str(affect.tracker_id)].append(str(affect.uuid))

        return AffectSerializerV1Optimized(
            instance=affects,
            many=True,
            read_only=True,
            context=self._build_nested_context(
                "affects", extra={"tracker_to_affects_map": tracker_to_affects_map}
            ),
        ).data

    @extend_schema_field(CommentSerializerV1Optimized(many=True))
    def get_comments(self, obj):
        return _serialize_prefetched(
            obj, "comments", CommentSerializerV1Optimized, self.context
        )

    @extend_schema_field(FlawAcknowledgmentSerializerV1Optimized(many=True))
    def get_acknowledgments(self, obj):
        return _serialize_prefetched(
            obj,
            "acknowledgments",
            FlawAcknowledgmentSerializerV1Optimized,
            self._build_nested_context("acknowledgments"),
        )

    @extend_schema_field(FlawReferenceSerializerV1Optimized(many=True))
    def get_references(self, obj):
        return _serialize_prefetched(
            obj,
            "references",
            FlawReferenceSerializerV1Optimized,
            self._build_nested_context("references"),
        )

    @extend_schema_field(FlawCVSSSerializerV1Optimized(many=True))
    def get_cvss_scores(self, obj):
        return _serialize_prefetched(
            obj, "cvss_scores", FlawCVSSSerializerV1Optimized, self.context
        )

    @extend_schema_field(PackageSerializerV1Optimized(many=True))
    def get_package_versions(self, obj):
        return _serialize_prefetched(
            obj, "package_versions", PackageSerializerV1Optimized, self.context
        )

    @extend_schema_field(UpstreamDataSerializerV1Optimized(many=True))
    def get_upstream_data(self, obj):
        return _serialize_prefetched(
            obj,
            "upstream_data",
            UpstreamDataSerializerV1Optimized,
            self._build_nested_context("upstream_data"),
        )

    @extend_schema_field(FlawCollaboratorSerializerV1Optimized(many=True))
    def get_labels(self, obj):
        return _serialize_prefetched(
            obj, "labels_v2", FlawCollaboratorSerializerV1Optimized, self.context
        )

    class Meta:
        model = Flaw
        fields = [
            "uuid",
            "cve_id",
            "impact",
            "components",
            "title",
            "trackers",
            "comment_zero",
            "cve_description",
            "selected_cve_description",
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
            "upstream_data",
            "affects",
            "comments",
            "meta_attr",
            "aegis_meta",
            "package_versions",
            "acknowledgments",
            "references",
            "cvss_scores",
            "labels",
            "embargoed",
            "visibility",
            "created_dt",
            "updated_dt",
            "classification",
            "group_key",
            "owner",
            "task_key",
            "team_id",
            "alerts",
            "history",
        ]
