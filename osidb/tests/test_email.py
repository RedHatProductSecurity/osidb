"""
Tests for email notifications when major_incident_state changes to *_REQUESTED.
"""

from unittest.mock import Mock

import pytest
from django.core.mail.message import EmailMessage

from osidb.models import Flaw
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


class TestEmailOnIncidentRequest:
    """
    Tests for email notification when major_incident_state changes to *_REQUESTED.
    """

    @pytest.mark.enable_signals
    @pytest.mark.parametrize(
        "request_state,expected_incident_kind",
        [
            (
                Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED,
                "Major",
            ),
            (
                Flaw.FlawMajorIncident.EXPLOITS_KEV_REQUESTED,
                "Exploits",
            ),
            (
                Flaw.FlawMajorIncident.MINOR_INCIDENT_REQUESTED,
                "Minor",
            ),
        ],
    )
    def test_email_sent_on_new_flaw_with_requested_state(
        self, monkeypatch, request_state, expected_incident_kind
    ):
        """
        Test that an email is sent when creating a new flaw with
        any *_REQUESTED major_incident_state.
        """
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        flaw = FlawFactory(
            major_incident_state=request_state,
            cve_id="CVE-2024-1234",
        )

        # Verify the Celery task was called
        assert mock_async_send_email.called
        call_args = mock_async_send_email.call_args

        # Verify the payload structure
        payload = call_args.kwargs
        assert (
            payload["subject"]
            == f"{expected_incident_kind} incident requested for CVE-2024-1234"
        )
        assert (
            f"A new {expected_incident_kind} incident has been requested"
            in payload["body"]
        )
        assert str(flaw.uuid) in payload["body"] or "flaw-detail" in payload["body"]
        assert payload["to"] == ["bar@example.com"]  # Default from EmailSettings
        assert payload["reply_to"] == ["bar@example.com"]
        assert "href" in payload["body"]

    @pytest.mark.enable_signals
    def test_email_sent_on_new_flaw_without_cve_id(self, monkeypatch):
        """
        Test that an email is sent when creating a new flaw with
        *_REQUESTED state but no CVE ID (UUID fallback).
        """
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MINOR_INCIDENT_REQUESTED,
            cve_id=None,  # Test with UUID fallback
        )

        # Verify the Celery task was called
        assert mock_async_send_email.called
        call_args = mock_async_send_email.call_args

        # Verify the payload structure
        payload = call_args.kwargs
        assert payload["subject"] == f"Minor incident requested for {flaw.uuid}"
        # When CVE is None, UUID is used
        assert str(flaw.uuid) in payload["subject"]

    @pytest.mark.enable_signals
    @pytest.mark.parametrize(
        "request_state,expected_incident_kind",
        [
            (
                Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED,
                "Major",
            ),
            (
                Flaw.FlawMajorIncident.EXPLOITS_KEV_REQUESTED,
                "Exploits",
            ),
            (
                Flaw.FlawMajorIncident.MINOR_INCIDENT_REQUESTED,
                "Minor",
            ),
        ],
    )
    def test_email_sent_on_state_change_to_requested_state(
        self, monkeypatch, request_state, expected_incident_kind
    ):
        """
        Test that an email is sent when an existing flaw's major_incident_state
        changes to any *_REQUESTED state.
        """
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        # Create flaw with NOVALUE state
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            cve_id="CVE-2024-9999",
        )

        # Reset mock since creation might trigger it
        mock_async_send_email.reset_mock()

        # Change state to requested state
        flaw.major_incident_state = request_state
        flaw.save()

        # Verify the Celery task was called
        assert mock_async_send_email.called
        call_args = mock_async_send_email.call_args

        # Verify the payload structure
        payload = call_args.kwargs
        assert (
            payload["subject"]
            == f"{expected_incident_kind} incident requested for CVE-2024-9999"
        )
        assert (
            f"A new {expected_incident_kind} incident has been requested"
            in payload["body"]
        )
        assert "flaw-detail" in payload["body"] or str(flaw.uuid) in payload["body"]
        assert "href" in payload["body"]

    @pytest.mark.enable_signals
    def test_no_email_on_unchanged_requested_state(self, monkeypatch):
        """
        Test that no email is sent when major_incident_state is already
        *_REQUESTED and doesn't change.
        """
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        # Create flaw with MAJOR_INCIDENT_REQUESTED state
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED,
        )

        # Reset mock after creation
        mock_async_send_email.reset_mock()

        # Modify another field but keep the same major_incident_state
        flaw.title = "Updated title"
        flaw.save()

        # Verify no email was sent
        assert not mock_async_send_email.called

    @pytest.mark.enable_signals
    @pytest.mark.parametrize(
        "non_requested_state",
        [
            Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
            Flaw.FlawMajorIncident.MAJOR_INCIDENT_REJECTED,
            Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            Flaw.FlawMajorIncident.EXPLOITS_KEV_REJECTED,
            Flaw.FlawMajorIncident.MINOR_INCIDENT_APPROVED,
            Flaw.FlawMajorIncident.MINOR_INCIDENT_REJECTED,
            Flaw.FlawMajorIncident.NOVALUE,
        ],
    )
    def test_no_email_on_change_to_non_requested_state(
        self, monkeypatch, non_requested_state
    ):
        """
        Test that no email is sent when major_incident_state changes
        to a non-requested state (e.g., APPROVED, REJECTED, NOVALUE).
        """
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        # Create flaw with MAJOR_INCIDENT_REQUESTED state
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED,
        )

        # Reset mock after creation
        mock_async_send_email.reset_mock()

        # Change to non-requested state
        flaw.major_incident_state = non_requested_state
        flaw.save()

        # Verify no email was sent
        assert not mock_async_send_email.called

    @pytest.mark.enable_signals
    def test_email_url_contains_flaw_id(self, monkeypatch):
        """
        Test that the email body contains a URL to the flaw.
        """
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED,
            cve_id="CVE-2024-1234",
        )

        # Verify the Celery task was called
        assert mock_async_send_email.called
        call_args = mock_async_send_email.call_args

        # Verify the payload contains a URL
        payload = call_args.kwargs
        assert "href" in payload["body"]
        assert str(flaw.uuid) in payload["body"] or "flaw-detail" in payload["body"]

    @pytest.mark.enable_signals
    def test_email_message_kwargs_are_valid(self, monkeypatch):
        """
        Test that the kwargs passed to async_send_email.delay can be used
        to create a valid EmailMessage instance, verifying the payload structure.
        """
        mock_async_send_email = Mock()
        monkeypatch.setattr("osidb.tasks.async_send_email.delay", mock_async_send_email)

        _ = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED,
            cve_id="CVE-2024-1234",
        )

        # Verify the Celery task was called
        assert mock_async_send_email.called
        call_args = mock_async_send_email.call_args

        # Get the kwargs that were passed to async_send_email.delay
        payload = dict(call_args.kwargs)

        # Create EmailMessage with the unpacked payload - this should not raise
        email_message = EmailMessage(**payload)

        # Verify the email message was created successfully with correct attributes
        assert email_message.subject == payload["subject"]
        assert email_message.body == payload["body"]
        assert email_message.to == payload["to"]
        assert email_message.reply_to == payload["reply_to"]
        assert email_message.extra_headers == payload["headers"]

        # Verify the email can be stringified (validates message structure)
        assert str(email_message)
