from unittest.mock import patch

import pytest
from rest_framework import status
from rest_framework.test import APIClient

from osidb.models.abstract import Impact
from osidb.models.flaw import FlawSource
from regulatory_reporting.models.upstream import UpstreamNotification, UpstreamProject

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
