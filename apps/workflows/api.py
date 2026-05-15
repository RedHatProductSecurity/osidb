"""
Workflows API endpoints
"""

import logging

from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet

from osidb.api_views import RudimentaryUserPathLoggingMixin, get_valid_http_methods
from osidb.helpers import get_flaw_or_404

from .helpers import str2bool
from .serializers import (
    ClassificationWorkflowSerializer,
    RejectSerializer,
    WorkflowSerializer,
)
from .workflow import WorkflowFramework

logger = logging.getLogger(__name__)

DEPRECATION_MESSAGE = (
    "Workflow classification is now automatic based on flaw data. "
    "This endpoint no longer performs any state changes. "
    "To change workflow state, update the flaw data (owner, affects, trackers, etc.). "
    "Use GET /workflows/api/v2/workflows/{id} to view computed classification."
)


class DeprecatedWorkflowMixin:
    """
    Mixin to add deprecation warnings to workflow mutation endpoints.

    Adds Warning HTTP header and deprecated field to response data.
    """

    def add_deprecation_warning(self, response):
        """Add deprecation warning header and field to response"""
        # Add HTTP Warning header (299 = Miscellaneous Persistent Warning)
        response["Warning"] = f'299 - "Deprecated: {DEPRECATION_MESSAGE}"'

        # Add deprecated field to response data
        if isinstance(response.data, dict):
            response.data["deprecated"] = True
            response.data["deprecation_message"] = DEPRECATION_MESSAGE

        logger.warning(
            f"Deprecated workflow endpoint called: {self.__class__.__name__}"
        )

        return response


jira_api_key_header = OpenApiParameter(
    name="Jira-Api-Key",
    type=str,
    location=OpenApiParameter.HEADER,
    description="User generated api key for Jira authentication.",
)


bz_api_key_header = OpenApiParameter(
    name="Bugzilla-Api-Key",
    type=str,
    location=OpenApiParameter.HEADER,
    description="User generated api key for Bugzilla authentication.",
)


class index(RudimentaryUserPathLoggingMixin, APIView):
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


# TODO do we need this when Workflows is baked into OSIDB service ?
class healthy(RudimentaryUserPathLoggingMixin, APIView):
    """unauthenticated health check API endpoint"""

    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        """
        unauthenticated health check API endpoint
        """
        logger.info("getting status")
        return Response()


class adjust(DeprecatedWorkflowMixin, RudimentaryUserPathLoggingMixin, APIView):
    """workflow adjustion API endpoint (DEPRECATED - NO-OP)"""

    http_method_names = get_valid_http_methods(ModelViewSet)

    def post(self, request, pk):
        """
        workflow adjustion API endpoint

        DEPRECATED: Workflow classification is now automatic on every flaw save.
        This endpoint no longer performs any action - it only returns the current
        computed classification. This endpoint will be removed in a future version.

        To change workflow state, update the flaw data directly (owner, affects,
        trackers, etc.). Classification will update automatically.
        """
        logger.info(f"[DEPRECATED NO-OP] adjust endpoint called for flaw {pk}")
        flaw = get_flaw_or_404(pk)
        # Do NOT call adjust_classification() - just return current state
        response = Response(
            {
                "flaw": flaw.pk,
                "classification": flaw.classification,
            }
        )
        return self.add_deprecation_warning(response)


class PromoteWorkflow(DeprecatedWorkflowMixin, RudimentaryUserPathLoggingMixin, APIView):
    """workflow promote API endpoint (DEPRECATED - NO-OP)"""

    @extend_schema(parameters=[jira_api_key_header, bz_api_key_header])
    def post(self, request, flaw_id):
        """
        workflow promotion API endpoint

        DEPRECATED: Workflow classification is now automatic based on flaw data.
        This endpoint no longer performs any action - it only returns the current
        computed classification. This endpoint will be removed in a future version.

        To change workflow state, update the flaw data directly (assign owner, create
        affects, file trackers, etc.). Classification will update automatically.
        """
        logger.info(f"[DEPRECATED NO-OP] promote endpoint called for flaw {flaw_id}")
        flaw = get_flaw_or_404(flaw_id)
        # Do NOT call promote() - just return current classification
        response = Response(
            {
                "flaw": flaw.pk,
                "classification": flaw.classification,
            }
        )
        return self.add_deprecation_warning(response)


class RevertWorkflow(DeprecatedWorkflowMixin, RudimentaryUserPathLoggingMixin, APIView):
    """workflow revert API endpoint (DEPRECATED - NO-OP)"""

    @extend_schema(parameters=[jira_api_key_header, bz_api_key_header])
    def post(self, request, flaw_id):
        """
        Workflow revert API endpoint.

        DEPRECATED: Workflow classification is now automatic based on flaw data.
        This endpoint no longer performs any action - it only returns the current
        computed classification. This endpoint will be removed in a future version.

        To change workflow state, update the flaw data directly. If requirements
        for the current state are no longer met, classification will automatically
        revert to the appropriate state.
        """
        logger.info(f"[DEPRECATED NO-OP] revert endpoint called for flaw {flaw_id}")
        flaw = get_flaw_or_404(flaw_id)
        # Do NOT call revert() - just return current classification
        response = Response(
            {
                "flaw": flaw.pk,
                "classification": flaw.classification,
            }
        )
        return self.add_deprecation_warning(response)


class ResetWorkflow(DeprecatedWorkflowMixin, RudimentaryUserPathLoggingMixin, APIView):
    """workflow reset API endpoint (DEPRECATED - NO-OP)"""

    @extend_schema(parameters=[jira_api_key_header, bz_api_key_header])
    def post(self, request, flaw_id):
        """
        Workflow reset API endpoint.

        DEPRECATED: Workflow classification is now automatic based on flaw data.
        This endpoint no longer performs any action - it only returns the current
        computed classification. This endpoint will be removed in a future version.

        Workflow state cannot be manually reset. Classification is determined by
        the flaw's current data and will automatically reflect the appropriate
        workflow and state.
        """
        logger.info(f"[DEPRECATED NO-OP] reset endpoint called for flaw {flaw_id}")
        flaw = get_flaw_or_404(flaw_id)
        # Do NOT call reset() - just return current classification
        response = Response(
            {
                "flaw": flaw.pk,
                "classification": flaw.classification,
            }
        )
        return self.add_deprecation_warning(response)


class RejectWorkflow(DeprecatedWorkflowMixin, RudimentaryUserPathLoggingMixin, APIView):
    """workflow reject API endpoint (DEPRECATED - NO-OP)"""

    @extend_schema(
        parameters=[jira_api_key_header, bz_api_key_header], request=RejectSerializer
    )
    def post(self, request, flaw_id):
        """
        workflow rejection API endpoint

        DEPRECATED: Workflow classification is now automatic based on flaw data.
        This endpoint no longer performs any action - it only returns the current
        computed classification. This endpoint will be removed in a future version.

        Rejection is driven by a flaw data TODO.
        """
        serializer = RejectSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        logger.info(f"[DEPRECATED NO-OP] reject endpoint called for flaw {flaw_id}")
        flaw = get_flaw_or_404(flaw_id)
        # Do NOT call reject() or create Jira comment - just return current classification
        response = Response(
            {
                "flaw": flaw.pk,
                "classification": flaw.classification,
            }
        )
        return self.add_deprecation_warning(response)


class classification(RudimentaryUserPathLoggingMixin, APIView):
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


class workflows(RudimentaryUserPathLoggingMixin, APIView):
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
