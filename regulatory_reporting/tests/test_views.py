from unittest.mock import patch

import pytest
from rest_framework.test import APIClient

from osidb.models.abstract import Impact
from osidb.models.flaw import FlawSource
from regulatory_reporting.models.upstream import UpstreamNotification

from .factories import (
    FlawFactory,
    NonReportableFlawFactory,
    UpstreamNotificationFactory,
    UpstreamProjectFactory,
)


class TestUpstreamNotificationView:
    def test_list_upstream_notifications(self, auth_client):
        """Test that endpoint returns upstream notifications."""
        UpstreamNotificationFactory()
        UpstreamNotificationFactory()

        response = auth_client().get("/osidb/api/v2/notifications/upstream")
        assert response.status_code == 200
        assert response.json()["count"] == 2

    def test_retrieve_upstream_notification(self, auth_client):
        """Test that endpoint returns a single notification."""
        notification = UpstreamNotificationFactory()

        response = auth_client().get(
            f"/osidb/api/v2/notifications/upstream/{notification.uuid}"
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

        response = auth_client().get("/osidb/api/v2/notifications/upstream?status=sent")
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
            "/osidb/api/v2/notifications/upstream?method=email"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 1

    def test_filter_by_upstream_project(self, auth_client):
        """Test filtering upstream notifications by upstream_project."""
        upstream_project = UpstreamProjectFactory()
        UpstreamNotificationFactory(upstream_project=upstream_project)
        UpstreamNotificationFactory()

        response = auth_client().get(
            f"/osidb/api/v2/notifications/upstream?upstream_project={upstream_project.uuid}"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 1

    def test_filter_by_flaw(self, auth_client):
        """Test filtering upstream notifications by flaw."""
        flaw = NonReportableFlawFactory()
        UpstreamNotificationFactory(flaw=flaw)
        UpstreamNotificationFactory()

        response = auth_client().get(
            f"/osidb/api/v2/notifications/upstream?flaw={flaw.uuid}"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 1

    def test_preview_returns_rendered_bodies(self, auth_client, test_api_v2_uri):
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
            f"{test_api_v2_uri}/notifications/upstream/{notification.uuid}/preview"
        )

        assert response.status_code == 200
        assert "text_body" in response.json()
        assert "html_body" in response.json()
        assert flaw.cve_description in response.json()["text_body"]
        assert upstream_project.component_name in response.json()["text_body"]

    def test_preview_without_upstream_project_fails(self, auth_client, test_api_v2_uri):
        """Test preview fails validation if no upstream project is linked."""
        flaw = NonReportableFlawFactory(cve_description="A test vulnerability.")
        notification = UpstreamNotificationFactory(
            flaw=flaw,
            upstream_project=None,
        )

        response = auth_client().get(
            f"{test_api_v2_uri}/notifications/upstream/{notification.uuid}/preview"
        )

        assert response.status_code == 400
        assert "upstream_project" in response.json()

    def test_preview_requires_authentication(self, test_api_v2_uri):
        """Test  anonymous requests to preview are rejected."""

        notification = UpstreamNotificationFactory()

        response = APIClient().get(
            f"{test_api_v2_uri}/notifications/upstream/{notification.uuid}/preview"
        )

        assert response.status_code == 401


@pytest.mark.no_cra_notifications
class TestUpstreamNotificationAPIDisabled:
    def test_list_returns_404_when_notifications_disabled(self, auth_client):
        """/osidb/api/v2/notifications/ 404s when CRA_NOTIFICATIONS_ENABLED is False."""
        response = auth_client().get("/osidb/api/v2/notifications/upstream")
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
            f"/osidb/api/v2/notifications/upstream/{notification.uuid}/send-email"
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
            f"/osidb/api/v2/notifications/upstream/{notification.uuid}/send-email"
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
            f"/osidb/api/v2/notifications/upstream/{notification.uuid}/send-email"
        )

        assert response.status_code == 400

    def test_send_email_wrong_method_fails(self, auth_client):
        """Test that send-email rejects notifications with non-email method."""
        notification = UpstreamNotificationFactory(
            method=UpstreamNotification.NotificationMethod.GITHUB_ISSUE,
            status=UpstreamNotification.NotificationStatus.REVIEWED,
        )

        response = auth_client().post(
            f"/osidb/api/v2/notifications/upstream/{notification.uuid}/send-email"
        )

        assert response.status_code == 400

    @patch("regulatory_reporting.api_views.upstream_notifications.async_send_email")
    def test_send_email_uses_new_template_fields(
        self, mock_task, auth_client, test_api_v2_uri
    ):
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
            f"{test_api_v2_uri}/notifications/upstream/{notification.uuid}/send-email"
        )

        assert response.status_code == 200
        notification.refresh_from_db()
        assert Impact.MODERATE in notification.payload_text
        assert flaw.mitigation in notification.payload_text
        assert upstream_project.security_contact in notification.payload_text
        assert "severity" not in notification.payload_text.lower()

    @patch("regulatory_reporting.api_views.upstream_notifications.async_send_email")
    def test_send_email_includes_confidentiality_notice_when_embargoed(
        self, mock_task, auth_client, test_api_v2_uri
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
            f"{test_api_v2_uri}/notifications/upstream/{notification.uuid}/send-email"
        )

        assert response.status_code == 200
        notification.refresh_from_db()
        assert (
            "This information is confidential until public disclosure."
            in notification.payload_text
        )
