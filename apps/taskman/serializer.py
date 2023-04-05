"""
Taskman requests serializers
"""
from rest_framework import serializers

from .service import TaskResolution, TaskStatus


class TaskCommentSerializer(serializers.Serializer):
    content = serializers.CharField(required=True)


class TaskGroupSerializer(serializers.Serializer):
    name = serializers.CharField(required=True)
    description = serializers.CharField()


class TaskKeySerializer(serializers.Serializer):
    task_key = serializers.CharField(required=True)


class StatusSerializer(serializers.Serializer):
    status = serializers.CharField(required=True)
    resolution = serializers.ChoiceField(choices=TaskResolution, required=False)
    reason = serializers.CharField(required=False)

    def validate(self, data):
        if data["status"] not in TaskStatus.values:
            raise serializers.ValidationError("Invalid status option.")
        if data["status"] == TaskStatus.CLOSED and not data["resolution"]:
            raise serializers.ValidationError("Closing a task requires a resolution.")
        elif (
            data["status"] == TaskStatus.CLOSED
            and data["resolution"] == TaskResolution.WONT_DO
            and "reason" not in data
        ):
            raise serializers.ValidationError("Rejecting a task requires a reason.")

        return data
