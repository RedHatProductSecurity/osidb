import logging
from datetime import timedelta
from unittest.mock import patch

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from osidb.models.abstract import Impact
from osidb.models.flaw import FlawSource
from regulatory_reporting.models.upstream import UpstreamNotification, UpstreamProject
from regulatory_reporting.tasks import (
    mark_upstream_notification_failed,
    mark_upstream_notification_sent,
)

from .factories import (
    NonReportableFlawFactory,
    UpstreamNotificationFactory,
    UpstreamProjectFactory,
)


class TestUpstreamNotificationView:
    def test_list_upstream_notifications(self, auth_client):
        """Test that endpoint returns upstream notifications."""
        UpstreamNotificationFactory()
        UpstreamNotificationFactory()

        response = auth_client().get(
            "/regulatory-reporting/api/v1/notifications/upstream"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 2

    def test_retrieve_upstream_notification(self, auth_client):
        """Test that endpoint returns a single notification."""
        notification = UpstreamNotificationFactory()

        response = auth_client().get(
            f"/regulatory-reporting/api/v1/notifications/upstream/{notification.uuid}"
        )
        assert response.status_code == 200
        assert response.json()["uuid"] == str(notification.uuid)

    def test_filter_by_status(self, auth_client):
        """Test filtering upstream notifications by status."""
        UpstreamNotificationFactory(
            status=UpstreamNotification.NotificationStatus.SENT,
        )
        UpstreamNotificationFactory(
            status=UpstreamNotification.NotificationStatus.REQUIRED,
        )

        response = auth_client().get(
            "/regulatory-reporting/api/v1/notifications/upstream?status=sent"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 1

    def test_filter_by_method(self, auth_client):
        """Test filtering upstream notifications by method."""
        UpstreamNotificationFactory(
            method=UpstreamNotification.NotificationMethod.EMAIL,
        )
        UpstreamNotificationFactory(
            method=UpstreamNotification.NotificationMethod.GITHUB_ISSUE,
        )

        response = auth_client().get(
            "/regulatory-reporting/api/v1/notifications/upstream?method=email"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 1

    def test_filter_by_upstream_project(self, auth_client):
        """Test filtering upstream notifications by upstream_project."""
        upstream_project = UpstreamProjectFactory()
        UpstreamNotificationFactory(upstream_project=upstream_project)
        UpstreamNotificationFactory()

        response = auth_client().get(
            f"/regulatory-reporting/api/v1/notifications/upstream?upstream_project={upstream_project.uuid}"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 1

    def test_filter_by_flaw(self, auth_client):
        """Test filtering upstream notifications by flaw."""
        flaw = NonReportableFlawFactory()
        UpstreamNotificationFactory(flaw=flaw)
        UpstreamNotificationFactory()

        response = auth_client().get(
            f"/regulatory-reporting/api/v1/notifications/upstream?flaw={flaw.uuid}"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 1

    def test_preview_returns_rendered_bodies(self, auth_client):
        """Test preview endpoint returns live rendered email."""
        flaw = NonReportableFlawFactory(cve_description="A test vulnerability.")
        upstream_project = UpstreamProjectFactory(
            component_name="example-lib",
            security_contact="security@example.com",
        )
        notification = UpstreamNotificationFactory(
            flaw=flaw,
            upstream_project=upstream_project,
        )

        response = auth_client().get(
            f"/regulatory-reporting/api/v1/notifications/upstream/{notification.uuid}/preview"
        )

        assert response.status_code == 200
        assert "text_body" in response.json()
        assert "html_body" in response.json()
        assert flaw.cve_description in response.json()["text_body"]
        assert upstream_project.component_name in response.json()["text_body"]

    def test_preview_without_upstream_project_fails(self, auth_client):
        """Test preview fails validation if no upstream project is linked."""
        flaw = NonReportableFlawFactory(cve_description="A test vulnerability.")
        notification = UpstreamNotificationFactory(
            flaw=flaw,
            upstream_project=None,
        )

        response = auth_client().get(
            f"/regulatory-reporting/api/v1/notifications/upstream/{notification.uuid}/preview"
        )

        assert response.status_code == 400
        assert "upstream_project" in response.json()

    def test_preview_requires_authentication(self):
        """Test  anonymous requests to preview are rejected."""

        notification = UpstreamNotificationFactory()

        response = APIClient().get(
            f"/regulatory-reporting/api/v1/notifications/upstream/{notification.uuid}/preview"
        )

        assert response.status_code == 401


class TestUpstreamNotificationFiltering:
    def test_filter_by_owner(self, auth_client):
        """Test that notifications can be filtered by owner (actor username)."""
        User = get_user_model()
        owner = User.objects.create(username="notification-owner")
        other_owner = User.objects.create(username="someone")

        target = UpstreamNotificationFactory(actor=owner)
        UpstreamNotificationFactory(actor=other_owner)
        UpstreamNotificationFactory()

        response = auth_client().get(
            "/regulatory-reporting/api/v1/notifications/upstream?owner=notification-owner"
        )

        assert response.status_code == 200
        results = response.json()["results"]
        assert len(results) == 1
        assert results[0]["uuid"] == str(target.uuid)


@pytest.mark.no_cra_notifications
class TestUpstreamNotificationAPIDisabled:
    def test_list_returns_404_when_notifications_disabled(self, auth_client):
        """/regulatory-reporting/api/v1/notifications/ 404s when CRA_NOTIFICATIONS_ENABLED is False."""
        response = auth_client().get(
            "/regulatory-reporting/api/v1/notifications/upstream"
        )
        assert response.status_code == 404


class TestSendEmailAction:
    @patch("regulatory_reporting.api_views.upstream_notifications.async_send_email")
    def test_send_email_success(self, mock_task, auth_client):
        """Test that send-email queues the email and updates status."""
        upstream_project = UpstreamProjectFactory(
            security_contact="maintainer@example.com"
        )
        flaw = NonReportableFlawFactory(source=FlawSource.REDHAT)
        notification = UpstreamNotificationFactory(
            flaw=flaw,
            upstream_project=upstream_project,
            method=UpstreamNotification.NotificationMethod.EMAIL,
            status=UpstreamNotification.NotificationStatus.REVIEWED,
        )

        response = auth_client().post(
            f"/regulatory-reporting/api/v1/notifications/upstream/{notification.uuid}/send-email"
        )

        assert response.status_code == 200
        notification.refresh_from_db()
        assert notification.status == UpstreamNotification.NotificationStatus.QUEUED
        assert notification.payload_text != ""
        mock_task.apply_async.assert_called_once()
        call_args = mock_task.apply_async.call_args
        assert (
            call_args.kwargs["link"].task
            == "regulatory_reporting.tasks.mark_upstream_notification_sent"
        )

    def test_send_email_wrong_status_fails(self, auth_client):
        """Test that send-email rejects notifications not in reviewed status."""
        notification = UpstreamNotificationFactory(
            method=UpstreamNotification.NotificationMethod.EMAIL,
            status=UpstreamNotification.NotificationStatus.REQUIRED,
        )

        response = auth_client().post(
            f"/regulatory-reporting/api/v1/notifications/upstream/{notification.uuid}/send-email"
        )

        assert response.status_code == 400

    def test_send_email_no_contact_fails(self, auth_client):
        """Test that send-email rejects notifications without a valid contact."""
        upstream_project = UpstreamProjectFactory(security_contact="")
        notification = UpstreamNotificationFactory(
            upstream_project=upstream_project,
            method=UpstreamNotification.NotificationMethod.EMAIL,
            status=UpstreamNotification.NotificationStatus.REVIEWED,
        )

        response = auth_client().post(
            f"/regulatory-reporting/api/v1/notifications/upstream/{notification.uuid}/send-email"
        )

        assert response.status_code == 400

    def test_send_email_wrong_method_fails(self, auth_client):
        """Test that send-email rejects notifications with non-email method."""
        notification = UpstreamNotificationFactory(
            method=UpstreamNotification.NotificationMethod.GITHUB_ISSUE,
            status=UpstreamNotification.NotificationStatus.REVIEWED,
        )

        response = auth_client().post(
            f"/regulatory-reporting/api/v1/notifications/upstream/{notification.uuid}/send-email"
        )

        assert response.status_code == 400

    @patch("regulatory_reporting.api_views.upstream_notifications.async_send_email")
    def test_send_email_uses_new_template_fields(self, mock_task, auth_client):
        """Test that send-email renders the new template fields."""
        upstream_project = UpstreamProjectFactory(
            security_contact="maintainer@example.com"
        )
        flaw = NonReportableFlawFactory(
            source=FlawSource.REDHAT,
            impact=Impact.MODERATE,
            mitigation="Upgrade to version 1.2.3",
        )
        notification = UpstreamNotificationFactory(
            flaw=flaw,
            upstream_project=upstream_project,
            method=UpstreamNotification.NotificationMethod.EMAIL,
            status=UpstreamNotification.NotificationStatus.REVIEWED,
        )

        response = auth_client().post(
            f"/regulatory-reporting/api/v1/notifications/upstream/{notification.uuid}/send-email"
        )

        assert response.status_code == 200
        notification.refresh_from_db()
        assert Impact.MODERATE in notification.payload_text
        assert flaw.mitigation in notification.payload_text
        assert upstream_project.security_contact in notification.payload_text
        assert "severity" not in notification.payload_text.lower()

    @patch("regulatory_reporting.api_views.upstream_notifications.async_send_email")
    def test_send_email_includes_confidentiality_notice_when_embargoed(
        self, mock_task, auth_client
    ):
        """Test that send-email includes the confidentiality notice for embargoed flaws."""
        upstream_project = UpstreamProjectFactory(
            security_contact="maintainer@example.com"
        )
        flaw = NonReportableFlawFactory(embargoed=True, source=FlawSource.REDHAT)
        notification = UpstreamNotificationFactory(
            flaw=flaw,
            upstream_project=upstream_project,
            method=UpstreamNotification.NotificationMethod.EMAIL,
            status=UpstreamNotification.NotificationStatus.REVIEWED,
        )

        response = auth_client().post(
            f"/regulatory-reporting/api/v1/notifications/upstream/{notification.uuid}/send-email"
        )

        assert response.status_code == 200
        notification.refresh_from_db()
        assert (
            "This information is confidential until public disclosure."
            in notification.payload_text
        )

    @patch("regulatory_reporting.api_views.upstream_notifications.async_send_email")
    def test_send_email_sets_actor(
        self, mock_task, auth_client, test_api_v2_uri, ldap_test_username
    ):
        """Test for send-email records the requesting user as actor."""
        upstream_project = UpstreamProjectFactory(
            security_contact="maintainer@example.com"
        )
        flaw = NonReportableFlawFactory(embargoed=False, source=FlawSource.REDHAT)
        notification = UpstreamNotificationFactory(
            flaw=flaw,
            upstream_project=upstream_project,
            method=UpstreamNotification.NotificationMethod.EMAIL,
            status=UpstreamNotification.NotificationStatus.REVIEWED,
        )

        response = auth_client().post(
            f"/regulatory-reporting/api/v1/notifications/upstream/{notification.uuid}/send-email"
        )

        assert response.status_code == 200
        notification.refresh_from_db()
        assert notification.actor is not None
        assert notification.actor.username == ldap_test_username

    @patch("regulatory_reporting.api_views.upstream_notifications.async_send_email")
    def test_send_email_sender_address(self, mock_task, auth_client, test_api_v2_uri):
        """Test for send-email sets the correct sender address."""
        upstream_project = UpstreamProjectFactory(
            security_contact="maintainer@example.com"
        )
        flaw = NonReportableFlawFactory(embargoed=False, source=FlawSource.REDHAT)
        notification = UpstreamNotificationFactory(
            flaw=flaw,
            upstream_project=upstream_project,
            method=UpstreamNotification.NotificationMethod.EMAIL,
            status=UpstreamNotification.NotificationStatus.REVIEWED,
        )

        auth_client().post(
            f"/regulatory-reporting/api/v1/notifications/upstream/{notification.uuid}/send-email"
        )

        call_args = mock_task.apply_async.call_args
        assert (
            call_args.kwargs["kwargs"]["from"] == settings.UPSTREAM_NOTIFICATIONS_SENDER
        )


class TestUpstreamNotificationTasks:
    def test_mark_upstream_notification_sent_sets_sent_at(self):
        """Test for the success callback records sent_at."""
        notification = UpstreamNotificationFactory(
            status=UpstreamNotification.NotificationStatus.QUEUED,
        )
        mark_upstream_notification_sent(
            result=1, notification_uuid=str(notification.uuid)
        )
        notification.refresh_from_db()
        assert notification.status == UpstreamNotification.NotificationStatus.SENT
        assert notification.sent_at is not None

    def test_mark_upstream_notification_failed_does_not_set_sent_at(self):
        """Test for the failure callback leaves sent_at unset."""
        notification = UpstreamNotificationFactory(
            status=UpstreamNotification.NotificationStatus.QUEUED,
        )
        mark_upstream_notification_failed(
            request=None,
            exc=Exception("SMTP error"),
            traceback=None,
            notification_uuid=str(notification.uuid),
        )
        notification.refresh_from_db()
        assert notification.status == UpstreamNotification.NotificationStatus.FAILED
        assert notification.sent_at is None

    def test_mark_upstream_notification_sent_does_not_overwrite_failed(self):
        """Test that a delayed success callback doesn't overwrite an already-failed record."""
        notification = UpstreamNotificationFactory(
            status=UpstreamNotification.NotificationStatus.FAILED,
            last_error="original error",
        )
        mark_upstream_notification_sent(
            result=1, notification_uuid=str(notification.uuid)
        )
        notification.refresh_from_db()
        assert notification.status == UpstreamNotification.NotificationStatus.FAILED
        assert notification.last_error == "original error"
        assert notification.sent_at is None

    def test_mark_upstream_notification_failed_does_not_overwrite_sent(self):
        """Test that a delayed failure callback doesn't overwrite an already-sent record."""
        notification = UpstreamNotificationFactory(
            status=UpstreamNotification.NotificationStatus.SENT,
        )
        mark_upstream_notification_failed(
            request=None,
            exc=Exception("late SMTP error"),
            traceback=None,
            notification_uuid=str(notification.uuid),
        )
        notification.refresh_from_db()
        assert notification.status == UpstreamNotification.NotificationStatus.SENT
        assert notification.last_error == ""

    def test_mark_upstream_notification_sent_logs_success(self, caplog):
        """Test for success callback logs an info message."""
        notification = UpstreamNotificationFactory(
            status=UpstreamNotification.NotificationStatus.QUEUED
        )
        task_logger = logging.getLogger("regulatory_reporting.tasks")
        task_logger.addHandler(caplog.handler)
        try:
            with caplog.at_level(logging.INFO, logger="regulatory_reporting.tasks"):
                mark_upstream_notification_sent(None, notification.uuid)
        finally:
            task_logger.removeHandler(caplog.handler)
        notification.refresh_from_db()
        assert notification.status == UpstreamNotification.NotificationStatus.SENT
        assert any(
            str(notification.uuid) in record.getMessage() and record.levelname == "INFO"
            for record in caplog.records
        )

    def test_mark_upstream_notification_failed_logs_error(self, caplog):
        """Test for failure callback logs an error message."""
        notification = UpstreamNotificationFactory(
            status=UpstreamNotification.NotificationStatus.QUEUED
        )
        exc = Exception("SMTP connection refused")
        task_logger = logging.getLogger("regulatory_reporting.tasks")
        task_logger.addHandler(caplog.handler)
        try:
            with caplog.at_level(logging.ERROR, logger="regulatory_reporting.tasks"):
                mark_upstream_notification_failed(None, exc, None, notification.uuid)
        finally:
            task_logger.removeHandler(caplog.handler)
        notification.refresh_from_db()
        assert notification.status == UpstreamNotification.NotificationStatus.FAILED
        assert any(
            str(notification.uuid) in record.getMessage()
            and "Exception" in record.getMessage()
            and record.levelname == "ERROR"
            for record in caplog.records
        )

    def test_open_excludes_terminal_statuses(self):
        """Test for open() excludes notifications in terminal statuses."""
        open_notification = UpstreamNotificationFactory(
            status=UpstreamNotification.NotificationStatus.REQUIRED
        )
        for terminal_status in [
            UpstreamNotification.NotificationStatus.NOT_APPLICABLE,
            UpstreamNotification.NotificationStatus.NOT_REQUIRED,
            UpstreamNotification.NotificationStatus.SENT,
        ]:
            UpstreamNotificationFactory(status=terminal_status)

        result = UpstreamNotification.objects.open()

        assert open_notification in result
        assert result.count() == 1

    def test_stale_excludes_recently_updated(self):
        """Test for stale() only returns notifications not updated since the given time."""
        old_notification = UpstreamNotificationFactory()
        UpstreamNotification.objects.filter(uuid=old_notification.uuid).update(
            updated_dt=timezone.now() - timedelta(days=10)
        )
        recent_notification = UpstreamNotificationFactory()

        cutoff = timezone.now() - timedelta(days=7)
        result = UpstreamNotification.objects.stale(cutoff)

        assert old_notification in result
        assert recent_notification not in result


class TestUpstreamProjectView:
    def test_list_upstream_projects(self, auth_client):
        UpstreamProjectFactory.create_batch(3)

        response = auth_client().get("/regulatory-reporting/api/v1/upstream-projects")

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 3

    def test_retrieve_upstream_project(self, auth_client):
        project = UpstreamProjectFactory()

        response = auth_client().get(
            f"/regulatory-reporting/api/v1/upstream-projects/{project.uuid}"
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["uuid"] == str(project.uuid)
        assert response.json()["component_name"] == project.component_name

    def test_create_upstream_project(self, auth_client):
        payload = {
            "component_name": "test-component",
            "repository_url": "https://github.com/test/test",
            "security_contact": "security@test.com",
            "contact_method": "email",
        }

        response = auth_client().post(
            "/regulatory-reporting/api/v1/upstream-projects", payload, format="json"
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert UpstreamProject.objects.filter(component_name="test-component").exists()

    def test_update_upstream_project(self, auth_client):
        project = UpstreamProjectFactory(component_name="old-name")

        response = auth_client().put(
            f"/regulatory-reporting/api/v1/upstream-projects/{project.uuid}",
            {
                "component_name": "new-name",
                "repository_url": project.repository_url,
                "security_contact": project.security_contact,
                "contact_method": project.contact_method,
                "updated_dt": project.updated_dt.isoformat(),
            },
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK
        project.refresh_from_db()
        assert project.component_name == "new-name"

    def test_filter_by_component(self, auth_client):
        UpstreamProjectFactory(component_name="curl")
        UpstreamProjectFactory(component_name="openssl")

        response = auth_client().get(
            "/regulatory-reporting/api/v1/upstream-projects?component=curl"
        )

        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 1
        assert results[0]["component_name"] == "curl"

    def test_filter_by_repository_url(self, auth_client):
        UpstreamProjectFactory(repository_url="https://github.com/test/curl")
        UpstreamProjectFactory(repository_url="https://github.com/test/openssl")

        response = auth_client().get(
            "/regulatory-reporting/api/v1/upstream-projects?repository_url=curl"
        )

        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 1
        assert "curl" in results[0]["repository_url"]

    def test_filter_by_purl(self, auth_client):
        UpstreamProjectFactory(purl="pkg:github/example/repo")
        response = auth_client().get(
            "/regulatory-reporting/api/v1/upstream-projects?purl=pkg:github/example/repo"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 1
        assert results[0]["purl"] == "pkg:github/example/repo"
