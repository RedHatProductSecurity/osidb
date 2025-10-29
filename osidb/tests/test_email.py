"""
Tests for email notifications when major_incident_state changes.
"""

from unittest.mock import Mock

import pytest
from django.core.mail.message import EmailMessage

from osidb.models import Flaw
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
