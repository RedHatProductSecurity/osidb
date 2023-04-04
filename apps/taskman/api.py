"""
Taskman API endpoints
"""
import logging

from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.taskman.constants import JIRA_TASKMAN_PROJECT_KEY, JIRA_TASKMAN_URL
from osidb.models import Flaw

from .jira_serializer import (
    JiraCommentSerializer,
    JiraIssueQueryResultSerializer,
    JiraIssueSerializer,
)
from .serializer import (
    StatusSerializer,
    TaskCommentSerializer,
    TaskGroupSerializer,
    TaskKeySerializer,
)
from .service import JiraTaskmanQuerier, TaskStatus

logger = logging.getLogger(__name__)

jira_token_description = extend_schema(
    parameters=[
        OpenApiParameter(
            name="JiraAuthentication",
            required=True,
            type=str,
            location=OpenApiParameter.HEADER,
            description="User generated token for Jira authentication.",
        ),
    ],
)


class healthy(APIView):
    """
    Taskman health check unauthenticated endpoint
    """

    permission_classes = [AllowAny]

    def __init__(self) -> None:
        self._is_healthy = True
        if not JIRA_TASKMAN_URL or not JIRA_TASKMAN_PROJECT_KEY:
            self._is_healthy = False

    def get(self, request, *args, **kwargs):
        """
        unauthenticated health check API endpoint
        """
        logger.info("getting status")
        status_code = 200 if self._is_healthy else 409
        status_str = "ok" if self._is_healthy else "error"
        return Response(data={"status": status_str}, status=status_code)


@jira_token_description
class task(GenericAPIView):
    """
    API endpoint for getting tasks by its key
    """

    @extend_schema(
        responses=JiraIssueSerializer,
    )
    def get(self, request, task_key):
        """Get a task from Jira given a task key"""
        return JiraTaskmanQuerier(
            token=request.headers.get("JiraAuthentication")
        ).get_task(task_key)


@jira_token_description
class task_comment_new(GenericAPIView):
    @extend_schema(
        parameters=[
            OpenApiParameter(name="content", required=True, type=str),
        ],
        description="Create a new comment in a task",
        responses=JiraCommentSerializer,
    )
    def post(self, request, task_key):
        serializer = TaskCommentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return JiraTaskmanQuerier(
            token=request.headers.get("JiraAuthentication")
        ).create_comment(
            issue_key=task_key,
            body=request.data["content"],
        )


@jira_token_description
class task_comment(GenericAPIView):
    @extend_schema(
        parameters=[
            OpenApiParameter(name="content", required=True, type=str),
        ],
        description="Edit a comment in a task",
        responses=JiraCommentSerializer,
    )
    def put(self, request, task_key, comment_id):
        """Get a task from Jira given a task key"""
        serializer = TaskCommentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return JiraTaskmanQuerier(
            token=request.headers.get("JiraAuthentication")
        ).update_comment(
            issue_key=task_key,
            comment_id=comment_id,
            body=serializer.validated_data["content"],
        )


@jira_token_description
class task_group_new(GenericAPIView):
    @extend_schema(
        parameters=[
            OpenApiParameter(name="name", required=True, type=str),
            OpenApiParameter(name="description", type=str),
        ],
        description="Create a new group of tasks",
        responses=JiraIssueSerializer,
    )
    def post(self, request):
        serializer = TaskGroupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        return JiraTaskmanQuerier(
            token=request.headers.get("JiraAuthentication")
        ).create_group(
            name=serializer.validated_data["name"],
            description=serializer.validated_data["description"],
        )


@jira_token_description
class task_group(GenericAPIView):
    @extend_schema(
        responses=JiraIssueQueryResultSerializer,
    )
    def get(self, request, group_key):
        """Get a list of tasks from a group"""
        return JiraTaskmanQuerier(
            token=request.headers.get("JiraAuthentication")
        ).search_task_by_group(group_key)

    @extend_schema(
        parameters=[
            OpenApiParameter(name="task_key", required=True, type=str),
        ],
        description="Add a task into a group",
        responses={204: OpenApiResponse(description="Modified.")},
    )
    def put(self, request, group_key):
        serializer = TaskKeySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return JiraTaskmanQuerier(
            token=request.headers.get("JiraAuthentication")
        ).add_task_into_group(
            issue_key=serializer.validated_data["task_key"], group_key=group_key
        )


@jira_token_description
class task_flaw(GenericAPIView):
    """
    API endpoint for interacting with tasks using a Flaw entity
    """

    @extend_schema(
        responses=JiraIssueSerializer,
    )
    def get(self, request, flaw_uuid):
        """Get a task from Jira given a Flaw uuid"""
        return JiraTaskmanQuerier(
            token=request.headers.get("JiraAuthentication")
        ).get_task_by_flaw(flaw_uuid)

    def post(self, request, flaw_uuid):
        """Create a task in Jira from a Flaw"""
        flaw = Flaw.objects.get(uuid=flaw_uuid)
        return JiraTaskmanQuerier(
            token=request.headers.get("JiraAuthentication")
        ).create_or_update_task(flaw=flaw, fail_if_exists=True)

    @extend_schema(
        description="Update a task in Jira from a Flaw",
        responses={204: OpenApiResponse(description="Modified.")},
    )
    def put(self, request, flaw_uuid):
        """Update a task in Jira from a Flaw"""
        flaw = Flaw.objects.get(uuid=flaw_uuid)
        return JiraTaskmanQuerier(
            token=request.headers.get("JiraAuthentication")
        ).create_or_update_task(flaw=flaw, fail_if_exists=False)


@jira_token_description
class task_status(GenericAPIView):
    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="status", required=True, type=str, enum=TaskStatus.values
            ),
        ],
        description="Change a task workflow status",
        responses={204: OpenApiResponse(description="Modified.")},
    )
    def put(self, request, task_key):
        serializer = StatusSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return JiraTaskmanQuerier(
            token=request.headers.get("JiraAuthentication")
        ).update_task_status(
            issue_key=task_key, status=serializer.validated_data["status"]
        )
