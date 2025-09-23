"""
Taskman requests serializers
"""

from rest_framework import serializers

from osidb.serializer import AffectSerializer


class FlawUUIDListSerializer(serializers.Serializer):
    flaw_uuids = serializers.ListField(
        child=serializers.UUIDField(format="hex_verbose")
    )


class PsStreamSelectionSerializer(serializers.Serializer):
    ps_update_stream = serializers.CharField(required=True)
    selected = serializers.BooleanField()
    acked = serializers.BooleanField()
    eus = serializers.BooleanField()
    aus = serializers.BooleanField()


class ModuleComponentSerializer(serializers.Serializer):
    ps_module = serializers.CharField()
    ps_component = serializers.CharField()
    streams = PsStreamSelectionSerializer(many=True)
    selected = serializers.BooleanField()
    affect = AffectSerializer()


class StreamComponentSerializer(serializers.Serializer):
    ps_update_stream = serializers.CharField()
    ps_component = serializers.CharField()
    offer = PsStreamSelectionSerializer()
    selected = serializers.BooleanField()
    affect = AffectSerializer()


class TrackerSuggestionV1Serializer(serializers.Serializer):
    modules_components = ModuleComponentSerializer(many=True)
    not_applicable = AffectSerializer(many=True)


class TrackerSuggestionSerializer(serializers.Serializer):
    streams_components = StreamComponentSerializer(many=True)
    not_applicable = AffectSerializer(many=True)
