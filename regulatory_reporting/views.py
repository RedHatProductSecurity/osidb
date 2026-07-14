from contextlib import contextmanager

from django.template.loader import render_to_string
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema
from rest_framework import mixins, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.response import Response

from osidb.api_views import (
    RudimentaryUserPathLoggingMixin,
    get_valid_http_methods,
    include_exclude_fields_extend_schema_view,
)
from osidb.tasks import async_send_email

from .filters import UpstreamNotificationFilter, UpstreamProjectFilter
from .models.upstream import UpstreamNotification, UpstreamProject
from .serializers.upstream import (
    UpstreamNotificationSerializer,
    UpstreamProjectSerializer,
)
from .tasks import mark_upstream_notification_failed, mark_upstream_notification_sent


@include_exclude_fields_extend_schema_view
class UpstreamNotificationView(
    RudimentaryUserPathLoggingMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """
    API endpoint for listing, creating, retrieving, and updating upstream maintainer notifications.
    """

    http_method_names = get_valid_http_methods(
        viewsets.GenericViewSet, excluded=["delete"]
    )
    queryset = UpstreamNotification.objects.all()
    serializer_class = UpstreamNotificationSerializer
    filter_backends = (DjangoFilterBackend,)
    filterset_class = UpstreamNotificationFilter
    lookup_url_kwarg = "notification_uuid"
    permission_classes = [IsAuthenticatedOrReadOnly]

    @extend_schema(request=None)
    @action(detail=True, methods=["post"], url_path="send-email")
    def send_email(self, request, notification_uuid=None):
        notification = self.get_object()

        if notification.method != UpstreamNotification.NotificationMethod.EMAIL:
            raise ValidationError({"method": "Notification method must be 'email'."})
        if notification.status != UpstreamNotification.NotificationStatus.REVIEWED:
            raise ValidationError({"status": "Notification status must be 'reviewed'."})

        upstream_project = notification.upstream_project
        if not upstream_project or not upstream_project.security_contact:
            raise ValidationError(
                {
                    "upstream_project": "Upstream project must have a valid email contact."
                }
            )

        flaw = notification.flaw
        flaw_id = flaw.cve_id or flaw.uuid

        context = {
            "flaw_id": flaw_id,
            "vulnerability_summary": flaw.title,
            "upstream_component": upstream_project.component_name,
            "severity": flaw.impact,
            "exploitation_state": "",
            "embargo_notice": "This flaw is currently embargoed."
            if flaw.is_embargoed
            else "",
            "corrective_measure": "",
        }

        text_body = render_to_string("email/upstream_notification.txt", context=context)
        html_body = render_to_string(
            "email/upstream_notification.html", context=context
        )

        payload = {
            "subject": f"Security notification for {flaw_id}",
            "to": [upstream_project.security_contact],
            "body": text_body,
        }

        updated_count = UpstreamNotification.objects.filter(
            uuid=notification.uuid,
            status=UpstreamNotification.NotificationStatus.REVIEWED,
        ).update(
            payload_text=text_body,
            status=UpstreamNotification.NotificationStatus.QUEUED,
            last_error="",
            updated_dt=timezone.now(),
        )

        if updated_count == 0:
            raise ValidationError({"status": "Notification status must be 'reviewed'."})

        notification.refresh_from_db()

        try:
            async_send_email.apply_async(
                kwargs={**payload, "html_body": html_body},
                link=mark_upstream_notification_sent.s(str(notification.uuid)),
                link_error=mark_upstream_notification_failed.s(
                    notification_uuid=str(notification.uuid)
                ),
            )
        except Exception:
            UpstreamNotification.objects.filter(
                uuid=notification.uuid,
                status=UpstreamNotification.NotificationStatus.QUEUED,
            ).update(
                status=UpstreamNotification.NotificationStatus.REVIEWED,
                payload_text="",
            )
            raise

        return Response(self.get_serializer(notification).data, status=200)


@contextmanager
def _redact_query_string_for_logging(request):
    """
    Temporarily clears the request's query string so that it filters sensitive values
    """
    request.GET  # noqa: B018
    original_query_string = request.META.get("QUERY_STRING", "")
    request.META["QUERY_STRING"] = ""
    try:
        yield
    finally:
        request.META["QUERY_STRING"] = original_query_string


@include_exclude_fields_extend_schema_view
class UpstreamProjectView(RudimentaryUserPathLoggingMixin, viewsets.ModelViewSet):
    """
    API endpoint for listing, creating, retrieving, and updating upstream project.
    """

    http_method_names = get_valid_http_methods(
        viewsets.ModelViewSet, excluded=["delete"]
    )
    queryset = UpstreamProject.objects.all()
    serializer_class = UpstreamProjectSerializer
    filter_backends = (DjangoFilterBackend,)
    filterset_class = UpstreamProjectFilter
    lookup_url_kwarg = "upstream_project_uuid"
    permission_classes = [IsAuthenticatedOrReadOnly]

    def initialize_request(self, request, *args, **kwargs):
        with _redact_query_string_for_logging(request):
            return super().initialize_request(request, *args, **kwargs)
