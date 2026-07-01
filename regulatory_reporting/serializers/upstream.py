from rest_framework import serializers

from osidb.serializer import ACLMixinSerializer, TrackingMixinSerializer
from regulatory_reporting.models.upstream import (
    FlawUpstreamMapping,
    UpstreamNotification,
    UpstreamProject,
)


class UpstreamProjectSerializer(TrackingMixinSerializer):
    uuid = serializers.UUIDField(read_only=True)

    class Meta:
        model = UpstreamProject
        fields = TrackingMixinSerializer.Meta.fields + [
            "uuid",
            "component_name",
            "repository_url",
            "security_contact",
            "contact_method",
            "contact_url",
            "source",
            "confidence",
            "verified_at",
            "verified_by",
            "unsupported",
            "stewarded_awareness",
            "stewarded_awareness_reason",
            "stewarded_awareness_marked_by",
            "stewarded_awareness_marked_at",
            "notes",
        ]


class FlawUpstreamMappingSerializer(TrackingMixinSerializer):
    uuid = serializers.UUIDField(read_only=True)
    flaw_uuid = serializers.UUIDField(read_only=True, source="flaw.uuid")

    class Meta:
        model = FlawUpstreamMapping
        fields = TrackingMixinSerializer.Meta.fields + [
            "uuid",
            "flaw_uuid",
            "upstream_project",
            "notes",
        ]


class UpstreamNotificationSerializer(ACLMixinSerializer, TrackingMixinSerializer):
    uuid = serializers.UUIDField(read_only=True)
    flaw_uuid = serializers.UUIDField(read_only=True, source="flaw.uuid")
    last_error = serializers.CharField(read_only=True)

    class Meta(ACLMixinSerializer.Meta, TrackingMixinSerializer.Meta):
        model = UpstreamNotification
        fields = (
            ACLMixinSerializer.Meta.fields
            + TrackingMixinSerializer.Meta.fields
            + [
                "uuid",
                "flaw_uuid",
                "upstream_project",
                "status",
                "reportability_reason",
                "method",
                "timer_started_at",
                "last_error",
            ]
        )
