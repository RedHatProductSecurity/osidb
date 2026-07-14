from unittest.mock import patch

import pytest
from rest_framework import status

from osidb.models.flaw import FlawSource
from osidb.tests.factories import FlawFactory
from regulatory_reporting.models.upstream import UpstreamNotification, UpstreamProject

from .factories import UpstreamNotificationFactory, UpstreamProjectFactory


@pytest.mark.no_cra_reporting
class TestUpstreamNotificationView:
    def test_list_upstream_notifications(self, auth_client, test_api_v2_uri):
        """Test that endpoint returns upstream notifications."""
        UpstreamNotificationFactory()
        UpstreamNotificationFactory()

        response = auth_client().get(f"{test_api_v2_uri}/notifications/upstream")
        assert response.status_code == 200
        assert response.json()["count"] == 2

    def test_retrieve_upstream_notification(self, auth_client, test_api_v2_uri):
        """Test that endpoint returns a single notification."""
        notification = UpstreamNotificationFactory()

        response = auth_client().get(
            f"{test_api_v2_uri}/notifications/upstream/{notification.uuid}"
        )
        assert response.status_code == 200
        assert response.json()["uuid"] == str(notification.uuid)

    def test_filter_by_status(self, auth_client, test_api_v2_uri):
        """Test filtering upstream notifications by status."""
        from regulatory_reporting.models.upstream import UpstreamNotification

        UpstreamNotificationFactory(status=UpstreamNotification.NotificationStatus.SENT)
        UpstreamNotificationFactory(
            status=UpstreamNotification.NotificationStatus.REQUIRED
        )

        response = auth_client().get(
            f"{test_api_v2_uri}/notifications/upstream?status=sent"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 1

    def test_filter_by_method(self, auth_client, test_api_v2_uri):
        """Test filtering upstream notifications by method."""
        UpstreamNotificationFactory(
            method=UpstreamNotification.NotificationMethod.EMAIL
        )
        UpstreamNotificationFactory(
            method=UpstreamNotification.NotificationMethod.GITHUB_ISSUE
        )

        response = auth_client().get(
            f"{test_api_v2_uri}/notifications/upstream?method=email"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 1

    def test_filter_by_upstream_project(self, auth_client, test_api_v2_uri):
        """Test filtering upstream notifications by upstream_project."""
        upstream_project = UpstreamProjectFactory()
        UpstreamNotificationFactory(upstream_project=upstream_project)
        UpstreamNotificationFactory()

        response = auth_client().get(
            f"{test_api_v2_uri}/notifications/upstream?upstream_project={upstream_project.uuid}"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 1

    def test_filter_by_flaw(self, auth_client, test_api_v2_uri):
        """Test filtering upstream notifications by flaw."""
        flaw = FlawFactory()
        UpstreamNotificationFactory(flaw=flaw)
        UpstreamNotificationFactory()

        response = auth_client().get(
            f"{test_api_v2_uri}/notifications/upstream?flaw={flaw.uuid}"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 1


@pytest.mark.no_cra_reporting
class TestSendEmailAction:
    @patch("regulatory_reporting.views.async_send_email")
    def test_send_email_success(self, mock_task, auth_client, test_api_v2_uri):
        """Test that send-email queues the email and updates status."""
        upstream_project = UpstreamProjectFactory(
            security_contact="maintainer@example.com"
        )
        flaw = FlawFactory(embargoed=False, source=FlawSource.REDHAT)
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
        assert notification.status == UpstreamNotification.NotificationStatus.QUEUED
        assert notification.payload_text != ""
        mock_task.apply_async.assert_called_once()
        call_args = mock_task.apply_async.call_args
        assert (
            call_args.kwargs["link"].task
            == "regulatory_reporting.tasks.mark_upstream_notification_sent"
        )

    def test_send_email_wrong_status_fails(self, auth_client, test_api_v2_uri):
        """Test that send-email rejects notifications not in reviewed status."""
        notification = UpstreamNotificationFactory(
            method=UpstreamNotification.NotificationMethod.EMAIL,
            status=UpstreamNotification.NotificationStatus.REQUIRED,
        )

        response = auth_client().post(
            f"{test_api_v2_uri}/notifications/upstream/{notification.uuid}/send-email"
        )

        assert response.status_code == 400

    def test_send_email_no_contact_fails(self, auth_client, test_api_v2_uri):
        """Test that send-email rejects notifications without a valid contact."""
        upstream_project = UpstreamProjectFactory(security_contact="")
        notification = UpstreamNotificationFactory(
            upstream_project=upstream_project,
            method=UpstreamNotification.NotificationMethod.EMAIL,
            status=UpstreamNotification.NotificationStatus.REVIEWED,
        )

        response = auth_client().post(
            f"{test_api_v2_uri}/notifications/upstream/{notification.uuid}/send-email"
        )

        assert response.status_code == 400

    def test_send_email_wrong_method_fails(self, auth_client, test_api_v2_uri):
        """Test that send-email rejects notifications with non-email method."""
        notification = UpstreamNotificationFactory(
            method=UpstreamNotification.NotificationMethod.GITHUB_ISSUE,
            status=UpstreamNotification.NotificationStatus.REVIEWED,
        )

        response = auth_client().post(
            f"{test_api_v2_uri}/notifications/upstream/{notification.uuid}/send-email"
        )

        assert response.status_code == 400


class TestUpstreamProjectView:
    def test_list_upstream_projects(self, auth_client, test_api_v2_uri):
        UpstreamProjectFactory.create_batch(3)

        response = auth_client().get(f"{test_api_v2_uri}/upstream-projects")

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 3

    def test_retrieve_upstream_project(self, auth_client, test_api_v2_uri):
        project = UpstreamProjectFactory()

        response = auth_client().get(
            f"{test_api_v2_uri}/upstream-projects/{project.uuid}"
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["uuid"] == str(project.uuid)
        assert response.json()["component_name"] == project.component_name

    def test_create_upstream_project(self, auth_client, test_api_v2_uri):
        payload = {
            "component_name": "test-component",
            "repository_url": "https://github.com/test/test",
            "security_contact": "security@test.com",
            "contact_method": "email",
        }

        response = auth_client().post(
            f"{test_api_v2_uri}/upstream-projects", payload, format="json"
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert UpstreamProject.objects.filter(component_name="test-component").exists()

    def test_update_upstream_project(self, auth_client, test_api_v2_uri):
        project = UpstreamProjectFactory(component_name="old-name")

        response = auth_client().put(
            f"{test_api_v2_uri}/upstream-projects/{project.uuid}",
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

    def test_filter_by_component(self, auth_client, test_api_v2_uri):
        UpstreamProjectFactory(component_name="curl")
        UpstreamProjectFactory(component_name="openssl")

        response = auth_client().get(
            f"{test_api_v2_uri}/upstream-projects?component=curl"
        )

        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 1
        assert results[0]["component_name"] == "curl"

    def test_filter_by_repository_url(self, auth_client, test_api_v2_uri):
        UpstreamProjectFactory(repository_url="https://github.com/test/curl")
        UpstreamProjectFactory(repository_url="https://github.com/test/openssl")

        response = auth_client().get(
            f"{test_api_v2_uri}/upstream-projects?repository_url=curl"
        )

        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 1
        assert "curl" in results[0]["repository_url"]

    def test_filter_by_purl_aliases_component(self, auth_client, test_api_v2_uri):
        UpstreamProjectFactory(component_name="curl")
        UpstreamProjectFactory(component_name="openssl")

        response = auth_client().get(f"{test_api_v2_uri}/upstream-projects?purl=curl")

        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 1
        assert results[0]["component_name"] == "curl"
