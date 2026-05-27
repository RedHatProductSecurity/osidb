"""
Workflows views
"""

import logging

from django.views.generic import TemplateView

from osidb.helpers import get_flaw_or_404

from .serializers import ClassificationWorkflowSerializer, WorkflowSerializer
from .workflow import WorkflowFramework

logger = logging.getLogger(__name__)


class workflows(TemplateView):
    """graph workflow view"""

    template_name = "graph.html"

    def get_context_data(self, **kwargs):
        return {
            "workflows": WorkflowSerializer(
                WorkflowFramework().workflows,
                many=True,
            ).data,
        }


class classification(TemplateView):
    """graph workflow view with flaw classification"""

    template_name = "graph.html"

    def get_context_data(self, **kwargs):
        flaw = get_flaw_or_404(kwargs["pk"])
        return {
            "workflows": ClassificationWorkflowSerializer(
                WorkflowFramework().workflows,
                context={"flaw": flaw},
                many=True,
            ).data,
        }
