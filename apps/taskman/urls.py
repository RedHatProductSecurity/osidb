"""
Taskman URLs
"""

import logging

from django.urls import path

from .api import (
    healthy,
    task,
    task_comment,
    task_comment_new,
    task_flaw,
    task_group,
    task_group_new,
    task_status,
)
from .constants import TASKMAN_API_VERSION

logger = logging.getLogger(__name__)

urlpatterns = [
    path("healthy", healthy.as_view()),
    path(f"api/{TASKMAN_API_VERSION}/task/flaw/<str:flaw_uuid>", task_flaw.as_view()),
    path(f"api/{TASKMAN_API_VERSION}/task/<str:task_key>", task.as_view()),
    path(
        f"api/{TASKMAN_API_VERSION}/task/<str:task_key>/status", task_status.as_view()
    ),
    path(
        f"api/{TASKMAN_API_VERSION}/task/<str:task_key>/comment",
        task_comment_new.as_view(),
    ),
    path(
        f"api/{TASKMAN_API_VERSION}/task/<str:task_key>/comment/<str:comment_id>",
        task_comment.as_view(),
    ),
    path(f"api/{TASKMAN_API_VERSION}/group", task_group_new.as_view()),
    path(f"api/{TASKMAN_API_VERSION}/group/<str:group_key>", task_group.as_view()),
]
