"""
Taskman requests serializers
"""
from drf_spectacular.utils import extend_schema_field
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


@extend_schema_field(AffectSerializer())
class ModuleComponentSerializer(serializers.Serializer):
    ps_module = serializers.UUIDField(format="hex_verbose")
    ps_component = serializers.UUIDField(format="hex_verbose")
    streams = serializers.ListField(child=PsStreamSelectionSerializer())
    selected = serializers.BooleanField()
    affect = serializers.SerializerMethodField()

    def get_affect(self, obj):
        """affects serializer getter"""
        context = {
            "include_fields": [],
            "exclude_fields": [],
            "include_meta_attr": [],
        }

        serializer = AffectSerializer(instance=obj["affect"], context=context)
        return serializer.data


@extend_schema_field(AffectSerializer(many=True))
class TrackerSuggestionSerializer(serializers.Serializer):
    modules_components = serializers.ListField(child=ModuleComponentSerializer())
    not_applicable = serializers.SerializerMethodField()

    def get_not_applicable(self, obj):
        """affects serializer getter"""
        affects = obj["not_applicable"].all()
        context = {
            "include_fields": [],
            "exclude_fields": [],
            "include_meta_attr": [],
        }

        serializer = AffectSerializer(instance=affects, many=True, context=context)
        return serializer.data
