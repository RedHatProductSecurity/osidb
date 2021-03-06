"""
OSIM API endpoints
"""

import logging

from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .helpers import get_flaw_or_404, str2bool
from .serializers import ClassificationWorkflowSerializer, WorkflowSerializer
from .workflow import WorkflowFramework

logger = logging.getLogger(__name__)


class index(APIView):
    """index API endpoint"""

    def get(self, request, *args, **kwargs):
        """index API endpoint listing available API endpoints"""
        logger.info("getting index")
        from .urls import urlpatterns

        return Response(
            {
                "index": [f"/{url.pattern}" for url in urlpatterns],
            }
        )


# TODO do we need this when OSIM is baked into OSIDB service ?
class healthy(APIView):
    """unauthenticated health check API endpoint"""

    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        """
        unauthenticated health check API endpoint
        """
        logger.info("getting status")
        return Response()


class adjust(APIView):
    """workflow adjustion API endpoint"""

    def post(self, request, pk):
        """
        workflow adjustion API endpoint

        adjust workflow classification of flaw identified by UUID or CVE
        and return its workflow:state classification (new if changed and old otherwise)

        adjust operation is idempotent so when the classification
        is already adjusted running it results in no operation
        """
        logger.info(f"adjusting flaw {pk} workflow classification")
        flaw = get_flaw_or_404(pk)
        flaw.adjust_classification()
        return Response(
            {
                "flaw": flaw.pk,
                "classification": flaw.classification,
            }
        )


class classification(APIView):
    """workflow classification API endpoint"""

    @extend_schema(
        parameters=[
            OpenApiParameter(
                "verbose",
                type={"type": "boolean"},
                location=OpenApiParameter.QUERY,
                description=(
                    "Return also workflows with flaw classification "
                    "which represents the reasoning of the result."
                ),
            ),
        ],
    )
    def get(self, request, pk):
        """
        workflow classification API endpoint

        for flaw identified by UUID or CVE returns its workflow:state classification

        params:

            verbose - return also workflows with flaw classification
                      which represents the reasoning of the result
        """
        logger.info(f"getting flaw {pk} workflow classification")
        flaw = get_flaw_or_404(pk)
        workflow, state = WorkflowFramework().classify(flaw)
        response = {
            "flaw": flaw.pk,
            "classification": {
                "workflow": workflow.name,
                "state": state.name,
            },
        }
        # optional verbose classification context
        verbose = request.GET.get("verbose")
        if verbose is not None:
            if str2bool(verbose, "verbose"):
                response["workflows"] = ClassificationWorkflowSerializer(
                    WorkflowFramework().workflows,
                    context={"flaw": flaw},
                    many=True,
                ).data
        return Response(response)


class workflows(APIView):
    """workflow info API endpoint"""

    def get(self, request, *args, **kwargs):
        """workflow info API endpoint"""
        logger.info("getting workflows")
        return Response(
            {
                "workflows": WorkflowSerializer(
                    WorkflowFramework().workflows,
                    many=True,
                ).data,
            }
        )
