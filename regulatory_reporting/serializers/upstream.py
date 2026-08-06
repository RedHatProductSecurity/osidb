from drf_spectacular.utils import extend_schema_serializer
from rest_framework import serializers

from osidb.serializer import (
    ACLMixinSerializer,
    EmbargoedField,
    IncludeExcludeFieldsMixin,
    TrackingMixinSerializer,
)
from regulatory_reporting.models.upstream import (
    FlawUpstreamMapping,
    UpstreamNotification,
    UpstreamProject,
)


class UpstreamProjectSerializer(TrackingMixinSerializer, IncludeExcludeFieldsMixin):
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
            "purl",
        ]


@extend_schema_serializer(exclude_fields=["updated_dt"])
class UpstreamProjectPostSerializer(UpstreamProjectSerializer):
    # Extra serializer for POST request as there is no last update
    ...


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


class UpstreamNotificationSerializer(
    ACLMixinSerializer, TrackingMixinSerializer, IncludeExcludeFieldsMixin
):
    uuid = serializers.UUIDField(read_only=True)
    flaw_uuid = serializers.UUIDField(read_only=True, source="flaw.uuid")
    last_error = serializers.CharField(read_only=True)
    # ACLs are inherited from the parent flaw (see signals.py); not mutable via
    # this API. Must be declared read_only: Meta.read_only_fields does not
    # apply to fields declared on ACLMixinSerializer. update() also skips
    # ACLMixinSerializer.update() so an omitted/spoofed embargoed value cannot
    # desynchronize this notification's ACLs from its parent flaw's.
    embargoed = EmbargoedField(
        source="*",
        read_only=True,
        help_text=(
            "The embargoed boolean attribute is technically read-only as it just "
            "indirectly modifies the ACLs but is mandatory as it controls the access "
            "to the resource."
        ),
    )

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

    def update(self, instance, validated_data, *args, **kwargs):
        """
        Preserve ACLs on update.

        ACLMixinSerializer.update() reads request.data.get("embargoed") and
        rewrites ACLs; omitting embargoed resolves as public. Notification
        ACLs are inherited from the parent flaw and are not mutable via this
        API.
        """
        validated_data["acl_read"] = instance.acl_read
        validated_data["acl_write"] = instance.acl_write
        return super(ACLMixinSerializer, self).update(
            instance, validated_data, *args, **kwargs
        )


class UpstreamNotificationPreviewSerializer(serializers.Serializer):
    text_body = serializers.CharField(read_only=True)
    html_body = serializers.CharField(read_only=True)
