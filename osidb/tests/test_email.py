"""
Tests for email notifications when major_incident_state changes.
"""

from unittest.mock import Mock

import pytest
from django.core.mail.message import EmailMessage

from apps.workflows.workflow import WorkflowModel
from osidb.models import Flaw, FlawCollaborator, FlawLabel
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


class TestEmailOnIncidentRequest:
    @pytest.mark.enable_signals
    def test_email_sent_on_new_flaw_with_non_novalue_state(self, monkeypatch):
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        _ = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
            cve_id="CVE-2024-1234",
        )

        assert mock_async_send_email.called
        call_args = mock_async_send_email.call_args

        payload = call_args.kwargs
        assert payload["subject"] == "Incident state change for Flaw CVE-2024-1234"
        assert "has been set to MAJOR_INCIDENT_APPROVED" in payload["body"]
        assert payload["to"] == ["bar@example.com"]  # Default from EmailSettings
        assert payload["reply_to"] == ["bar@example.com"]

    @pytest.mark.enable_signals
    def test_email_sent_on_new_flaw_without_cve_id(self, monkeypatch):
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MINOR_INCIDENT_REQUESTED,
            cve_id=None,
        )

        assert mock_async_send_email.called
        call_args = mock_async_send_email.call_args

        payload = call_args.kwargs
        assert payload["subject"] == f"Incident state change for Flaw {flaw.uuid}"
        assert "has been set to MINOR_INCIDENT_REQUESTED" in payload["body"]
        assert str(flaw.uuid) in payload["body"]

    @pytest.mark.enable_signals
    def test_no_email_on_new_flaw_with_novalue(self, monkeypatch):
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        _ = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            cve_id="CVE-2024-1234",
        )

        assert not mock_async_send_email.called

    @pytest.mark.enable_signals
    def test_email_sent_on_state_change(self, monkeypatch):
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED,
            cve_id="CVE-2024-9999",
        )

        mock_async_send_email.reset_mock()

        flaw.major_incident_state = Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED
        flaw.save()

        assert mock_async_send_email.called
        call_args = mock_async_send_email.call_args

        payload = call_args.kwargs
        assert payload["subject"] == "Incident state change for Flaw CVE-2024-9999"
        assert (
            "has been changed from MAJOR_INCIDENT_REQUESTED to MAJOR_INCIDENT_APPROVED"
            in payload["body"]
        )

    @pytest.mark.enable_signals
    def test_no_email_on_unchanged_requested_state(self, monkeypatch):
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED,
        )

        mock_async_send_email.reset_mock()

        flaw.title = "Updated title"
        flaw.save()

        assert not mock_async_send_email.called

    @pytest.mark.enable_signals
    def test_email_url_contains_flaw_id(self, monkeypatch):
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED,
            cve_id="CVE-2024-1234",
        )

        assert mock_async_send_email.called
        call_args = mock_async_send_email.call_args

        payload = call_args.kwargs
        assert "href" in payload["html_body"]
        assert flaw.cve_id in payload["html_body"]

    @pytest.mark.enable_signals
    def test_email_message_kwargs_are_valid(self, monkeypatch):
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        _ = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED,
            cve_id="CVE-2024-1234",
        )

        assert mock_async_send_email.called
        call_args = mock_async_send_email.call_args

        payload = dict(call_args.kwargs)
        payload.pop("html_body", None)

        email_message = EmailMessage(**payload)

        assert email_message.subject == payload["subject"]
        assert email_message.body == payload["body"]
        assert email_message.to == payload["to"]
        assert email_message.reply_to == payload["reply_to"]
        assert email_message.extra_headers == payload["headers"]

        assert str(email_message)


class TestEmailOnIncidentReviewRequest:
    @pytest.fixture(autouse=True)
    def setup(self):
        """
        Set up incident review labels.
        """
        FlawLabel.objects.create(
            name="incident_peer_review",
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )

        FlawLabel.objects.create(
            name="incident_management_review",
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )

    @pytest.mark.enable_signals
    @pytest.mark.parametrize(
        "incident_review_label", ["incident_peer_review", "incident_management_review"]
    )
    def test_email_incident_review_requested(self, monkeypatch, incident_review_label):
        """
        Test that creating incident review labels sends notifications.
        """
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        # Incident state set to none so that the notifications for incident
        # request doesn't trigger. This is to just test only the labels.
        flaw = FlawFactory(
            cve_id="CVE-2026-123456789",
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        flaw.workflow_state = WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        flaw.save()

        FlawCollaborator.objects.create(
            label=incident_review_label,
            flaw=flaw,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )

        assert mock_async_send_email.called

        call_args = mock_async_send_email.call_args

        payload = call_args.kwargs
        assert (
            payload["subject"]
            == "Request for contribution on incident - CVE-2026-123456789"
        )
        assert f"assigned as a {incident_review_label} contributor" in payload["body"]
        assert payload["to"] == ["bar@example.com"]
        assert payload["reply_to"] == ["bar@example.com"]

        assert "href" in payload["html_body"]
        assert flaw.cve_id in payload["html_body"]
        assert incident_review_label in payload["html_body"]

    @pytest.mark.enable_signals
    @pytest.mark.parametrize(
        "incident_review_label", ["incident_peer_review", "incident_management_review"]
    )
    def test_email_incident_review_message_kwargs_are_valid(
        self, monkeypatch, incident_review_label
    ):
        """
        Test that the arguments match when creating an email for incident
        review notification.
        """
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        flaw = FlawFactory(
            cve_id="CVE-2026-123456789",
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        flaw.workflow_state = WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        flaw.save()

        FlawCollaborator.objects.create(
            label=incident_review_label,
            flaw=flaw,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )

        assert mock_async_send_email.called
        call_args = mock_async_send_email.call_args

        payload = dict(call_args.kwargs)
        payload.pop("html_body", None)

        email_message = EmailMessage(**payload)

        assert email_message.subject == payload["subject"]
        assert email_message.body == payload["body"]
        assert email_message.to == payload["to"]
        assert email_message.reply_to == payload["reply_to"]
        assert email_message.extra_headers == payload["headers"]

        assert str(email_message)

    @pytest.mark.enable_signals
    @pytest.mark.parametrize(
        "incident_review_label", ["incident_peer_review", "incident_management_review"]
    )
    def test_no_email_incident_review_change(self, monkeypatch, incident_review_label):
        """
        Test that notifications are sent only during creation and not during updates.
        """
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        flaw = FlawFactory(
            cve_id="CVE-2026-123456789",
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        flaw.workflow_state = WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        flaw.save()

        review = FlawCollaborator.objects.create(
            label=incident_review_label,
            flaw=flaw,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )

        assert mock_async_send_email.called
        mock_async_send_email.reset_mock()

        review.state = FlawCollaborator.FlawCollaboratorState.DONE
        assert not mock_async_send_email.called
