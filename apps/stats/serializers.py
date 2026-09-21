from rest_framework import serializers


class StatsMetaSerializer(serializers.Serializer):
    total_flaws = serializers.IntegerField()
    sum_group_counts = serializers.IntegerField()
    group_by = serializers.ListField(child=serializers.CharField())
    filters = serializers.DictField()
    age_bucket_bounds = serializers.ListField(
        child=serializers.IntegerField(), required=False
    )
    generated_at = serializers.DateTimeField()


class StatsFlawsResponseSerializer(serializers.Serializer):
    groups = serializers.ListField(child=serializers.DictField())
    meta = StatsMetaSerializer()
