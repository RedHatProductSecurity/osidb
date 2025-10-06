"""
Workflows API endpoints
"""

import logging

from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet

from apps.taskman.service import JiraTaskmanQuerier
from osidb.api_views import RudimentaryUserPathLoggingMixin, get_valid_http_methods
from osidb.helpers import get_bugzilla_api_key, get_jira_api_key

from .exceptions import WorkflowsException
from .helpers import get_flaw_or_404, str2bool
from .serializers import (
    ClassificationWorkflowSerializer,
    RejectSerializer,
    WorkflowSerializer,
)
from .workflow import WorkflowFramework

logger = logging.getLogger(__name__)


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


class adjust(RudimentaryUserPathLoggingMixin, APIView):
    """workflow adjustion API endpoint"""

    http_method_names = get_valid_http_methods(ModelViewSet)

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


class PromoteWorkflow(RudimentaryUserPathLoggingMixin, APIView):
    """workflow promote API endpoint"""

    @extend_schema(parameters=[jira_api_key_header, bz_api_key_header])
    def post(self, request, flaw_id):
        """
        workflow promotion API endpoint

        try to adjust workflow classification of flaw to the next state available
        return its workflow:state classification or errors if not possible to promote
        """
        logger.info(f"promoting flaw {flaw_id} workflow classification")
        flaw = get_flaw_or_404(flaw_id)
        try:
            jira_token = get_jira_api_key(request)
            bz_token = get_bugzilla_api_key(request)
            flaw.promote(jira_token=jira_token, bz_api_key=bz_token)
            return Response(
                {
                    "flaw": flaw.pk,
                    "classification": flaw.classification,
                }
            )
        except WorkflowsException as e:
            return Response({"errors": str(e)}, status=status.HTTP_409_CONFLICT)


class RevertWorkflow(RudimentaryUserPathLoggingMixin, APIView):
    @extend_schema(parameters=[jira_api_key_header, bz_api_key_header])
    def post(self, request, flaw_id):
        """
        Workflow revert API endpoint.

        Try to adjust workflow classification of a Flaw to the previous state
        available and return its workflow:state classification or errors if
        not possible to revert.
        """
        logger.info(f"Reverting Flaw {flaw_id} workflow classification")
        flaw = get_flaw_or_404(flaw_id)
        try:
            jira_token = get_jira_api_key(request)
            bz_token = get_bugzilla_api_key(request)
            flaw.revert(jira_token=jira_token, bz_api_key=bz_token)
            return Response(
                {
                    "flaw": flaw.pk,
                    "classification": flaw.classification,
                }
            )
        except WorkflowsException as e:
            return Response({"errors": str(e)}, status=status.HTTP_409_CONFLICT)


class ResetWorkflow(RudimentaryUserPathLoggingMixin, APIView):
    @extend_schema(parameters=[jira_api_key_header, bz_api_key_header])
    def post(self, request, flaw_id):
        """
        Workflow reset API endpoint.

        Try to adjust workflow classification of a Flaw to the initial state
        of the default workflow, return its workflow:state classification or
        errors if not possible to reset.
        """
        logger.info(f"Resetting Flaw {flaw_id} workflow classification")
        flaw = get_flaw_or_404(flaw_id)
        try:
            jira_token = get_jira_api_key(request)
            bz_token = get_bugzilla_api_key(request)
            flaw.reset(jira_token=jira_token, bz_api_key=bz_token)
            return Response(
                {
                    "flaw": flaw.pk,
                    "classification": flaw.classification,
                }
            )
        except WorkflowsException as e:
            return Response({"errors": str(e)}, status=status.HTTP_409_CONFLICT)


class RejectWorkflow(RudimentaryUserPathLoggingMixin, APIView):
    """workflow reject API endpoint"""

    @extend_schema(
        parameters=[jira_api_key_header, bz_api_key_header], request=RejectSerializer
    )
    def post(self, request, flaw_id):
        """
        workflow promotion API endpoint

        try to reject a flaw / task
        """
        serializer = RejectSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        logger.info(f"rejecting flaw {flaw_id} workflow classification")
        flaw = get_flaw_or_404(flaw_id)
        try:
            jira_token = get_jira_api_key(request)
            bz_token = get_bugzilla_api_key(request)
            flaw.reject(jira_token=jira_token, bz_api_key=bz_token)
            JiraTaskmanQuerier(token=jira_token).create_comment(
                issue_key=flaw.task_key,
                body=request.data["reason"],
            )
            return Response(
                {
                    "flaw": flaw.pk,
                    "classification": flaw.classification,
                }
            )
        except WorkflowsException as e:
            return Response({"errors": str(e)}, status=status.HTTP_409_CONFLICT)


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
