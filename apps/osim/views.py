"""
OSIM views
"""

import logging

from django.shortcuts import render
from django.views.generic import ListView

from .helpers import get_flaw_or_404
from .models import Workflow
from .serializers import ClassificationWorkflowSerializer, WorkflowSerializer
from .workflow import WorkflowFramework

logger = logging.getLogger(__name__)


class workflows(ListView):
    """graph workflow view"""

    model = Workflow
    template_name = "graph.html"

    def get(self, request, *args, **kwargs):
        """HTTP get graph/workflows"""
        logger.info("getting workflow graphs")
        context = {
            "workflows": WorkflowSerializer(
                WorkflowFramework().workflows,
                many=True,
            ).data,
        }
        return render(request, "graph.html", context)


class classification(ListView):
    """graph workflow view with flaw classification"""

    model = Workflow
    template_name = "graph.html"

    def get(self, request, *args, **kwargs):
        """HTTP get graph/workflows/<str:pk>"""
        pk = kwargs["pk"]
        logger.info(f"getting workflow graphs with flaw {pk} classification")
        flaw = get_flaw_or_404(pk)
        context = {
            "workflows": ClassificationWorkflowSerializer(
                WorkflowFramework().workflows,
                context={"flaw": flaw},
                many=True,
            ).data,
        }
        return render(request, "graph.html", context)
