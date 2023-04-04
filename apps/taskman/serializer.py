"""
Taskman requests serializers
"""
from rest_framework import serializers

from .service import TaskStatus


class TaskCommentSerializer(serializers.Serializer):
    content = serializers.CharField(required=True)


class TaskGroupSerializer(serializers.Serializer):
    name = serializers.CharField(required=True)
    description = serializers.CharField()


class TaskKeySerializer(serializers.Serializer):
    task_key = serializers.CharField(required=True)


class StatusSerializer(serializers.Serializer):
    status = serializers.CharField(required=True)

    def validate(self, data):
        if data["status"] not in TaskStatus.values:
            raise serializers.ValidationError("Invalid status option.")
        return data
