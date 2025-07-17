"""
Workflows models serializers
"""

from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from .models import Check, Condition
from .workflow import WorkflowModel


class CheckSerializer(serializers.Serializer):
    """Check serializer"""

    name = serializers.CharField()
    description = serializers.CharField()


class ConditionSerializer(serializers.Serializer):
    """Condition serializer"""

    condition = serializers.CharField()
    requirements = serializers.ListField()

    def to_representation(self, instance):
        if isinstance(instance, Condition):
            return {
                "condition": instance.condition,
                "requirements": [
                    (
                        CheckSerializer(check).data
                        if isinstance(check, Check)
                        else ConditionSerializer(check).data
                    )
                    for check in instance.checks
                ],
            }
        return super().to_representation(instance)

    def to_internal_value(self, data):
        parsed_requirements = []
        for requirement in data.get("requirements", []):
            if "condition" in requirement:
                parsed_requirements.append(
                    ConditionSerializer().to_internal_value(requirement)
                )
            else:
                parsed_requirements.append(
                    CheckSerializer().to_internal_value(requirement)
                )

        return {
            "condition": data["condition"],
            "requirements": parsed_requirements,
        }


class StateSerializer(serializers.Serializer):
    """State serializer"""

    name = serializers.CharField()
    requirements = serializers.ListField()

    def to_representation(self, instance):
        return {
            "name": instance.name,
            "requirements": [
                (
                    CheckSerializer(req).data
                    if isinstance(req, Check)
                    else ConditionSerializer(req).data
                )
                for req in instance.requirements
            ],
        }

    def to_internal_value(self, data):
        parsed_requirements = []
        for requirement in data.get("requirements", []):
            if "condition" in requirement:
                parsed_requirements.append(
                    ConditionSerializer().to_internal_value(requirement)
                )
            else:
                parsed_requirements.append(
                    CheckSerializer().to_internal_value(requirement)
                )

        return {
            "name": data["name"],
            "requirements": parsed_requirements,
        }


class WorkflowSerializer(serializers.Serializer):
    """Workflow serializer"""

    name = serializers.CharField()
    description = serializers.CharField()
    priority = serializers.IntegerField()
    conditions = CheckSerializer(many=True)
    states = StateSerializer(many=True)


class ClassificationSerializer(serializers.Serializer):
    """
    classification serializer

    provides accepts boolean attribute stating whether the given flaw
    is accepted by the instance - which needs to provide accepts method

    this is a generic serializer made to extend other serializers
    """

    accepts = serializers.SerializerMethodField("_accepts")

    def _accepts(self, instance):
        flaw = self.context.get("flaw")
        return None if not flaw else instance.accepts(flaw)


class ClassificationCheckSerializer(ClassificationSerializer, CheckSerializer):
    """Check serializer with classification"""


class ClassificationStateSerializer(ClassificationSerializer, StateSerializer):
    """State serializer with classification"""

    requirements = ClassificationCheckSerializer(many=True)


class ClassificationWorkflowSerializer(ClassificationSerializer, WorkflowSerializer):
    """Workflow serializer with classification"""

    conditions = ClassificationCheckSerializer(many=True)
    states = ClassificationStateSerializer(many=True)


class RejectSerializer(serializers.Serializer):
    """Task rejection serializer"""

    reason = serializers.CharField()


class WorkflowModelSerializer(serializers.ModelSerializer):
    classification = serializers.SerializerMethodField()
    task_key = serializers.CharField(read_only=True, allow_null=True)

    class Meta:
        model = WorkflowModel
        fields = ["classification", "group_key", "owner", "task_key", "team_id"]
        abstract = True

    @extend_schema_field(
        {
            "type": "object",
            "properties": {
                "workflow": {"type": "string"},
                "state": {
                    "type": "string",
                    "enum": WorkflowModel.WorkflowState.values,
                },
            },
        }
    )
    def get_classification(self, obj):
        """workflow classification"""
        return obj.classification
