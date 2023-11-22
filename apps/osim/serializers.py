"""
OSIM models serializers
"""

from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from .workflow import WorkflowModel


class CheckSerializer(serializers.Serializer):
    """Check serializer"""

    name = serializers.CharField()
    description = serializers.CharField()


class StateSerializer(serializers.Serializer):
    """State serializer"""

    name = serializers.CharField()
    requirements = CheckSerializer(many=True)


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

    class Meta:
        model = WorkflowModel
        fields = ["classification"]
        abstract = True

    @extend_schema_field(
        {
            "type": "object",
            "properties": {
                "workflow": {"type": "string"},
                "state": {
                    "type": "string",
                    "enum": WorkflowModel.OSIMState.values,
                },
            },
        }
    )
    def get_classification(self, obj):
        """workflow classification"""
        return obj.classification
