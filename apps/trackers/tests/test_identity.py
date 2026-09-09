"""Tests for tracker filing identity / service-account reporter selection."""

import pytest
from rest_framework import serializers

from apps.ace.constants import LABEL_AUTO_AFFECTS, LABEL_MANUAL_TRIAGE
from apps.trackers.identity import (
    all_linked_flaws_auto_analyzed,
    filing_credentials,
    is_auto_analyzed_flaw,
)
from osidb.models import Tracker
from osidb.models.flaw.label import WorkflowLabel
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit

CALLER = ("caller-bz", "caller-jira", "caller@example.com")
SERVICE = ("service-bz", "service-jira", "service@example.com")


def _credentials(affects):
    return filing_credentials(
        affects,
        bz_api_key=CALLER[0],
        jira_token=CALLER[1],
        jira_email=CALLER[2],
    )


@pytest.fixture
def service_bts_env(monkeypatch):
    monkeypatch.setattr("collectors.bzimport.constants.BZ_API_KEY", SERVICE[0])
    monkeypatch.setattr("apps.taskman.constants.JIRA_AUTH_TOKEN", SERVICE[1])
    monkeypatch.setattr("apps.taskman.constants.JIRA_EMAIL", SERVICE[2])


class TestAutoAnalyzedDetection:
    def test_unlabeled_human_affect_is_not_auto_analyzed(self):
        affect = AffectFactory(flaw=FlawFactory(embargoed=False))
        assert is_auto_analyzed_flaw(affect.flaw) is False
        assert all_linked_flaws_auto_analyzed([affect]) is False

    def test_auto_affects_label(self):
        affect = AffectFactory(flaw=FlawFactory(embargoed=False))
        WorkflowLabel.objects.create(flaw=affect.flaw, name=LABEL_AUTO_AFFECTS)
        assert is_auto_analyzed_flaw(affect.flaw) is True
        assert all_linked_flaws_auto_analyzed([affect]) is True

    def test_ace_created_by(self):
        affect = AffectFactory(
            flaw=FlawFactory(embargoed=False),
            created_by="AffectCreationEngine",
        )
        assert is_auto_analyzed_flaw(affect.flaw) is True
        assert all_linked_flaws_auto_analyzed([affect]) is True

    def test_mixed_flaws_are_not_all_auto_analyzed(self):
        auto = AffectFactory(flaw=FlawFactory(embargoed=False))
        WorkflowLabel.objects.create(flaw=auto.flaw, name=LABEL_AUTO_AFFECTS)
        human = AffectFactory(flaw=FlawFactory(embargoed=False))
        assert all_linked_flaws_auto_analyzed([auto, human]) is False

    def test_manual_triage_is_not_auto_analyzed(self):
        affect = AffectFactory(flaw=FlawFactory(embargoed=False))
        WorkflowLabel.objects.create(flaw=affect.flaw, name=LABEL_MANUAL_TRIAGE)
        assert is_auto_analyzed_flaw(affect.flaw) is False
        assert all_linked_flaws_auto_analyzed([affect]) is False

    def test_empty_affects(self):
        assert all_linked_flaws_auto_analyzed([]) is False
        assert all_linked_flaws_auto_analyzed(None) is False


class TestFilingCredentials:
    def test_human_keeps_caller(self, service_bts_env):
        affect = AffectFactory(flaw=FlawFactory(embargoed=False))
        assert _credentials([affect]) == CALLER

    def test_auto_affects_uses_service(self, service_bts_env):
        affect = AffectFactory(flaw=FlawFactory(embargoed=False))
        WorkflowLabel.objects.create(flaw=affect.flaw, name=LABEL_AUTO_AFFECTS)
        assert _credentials([affect]) == SERVICE

    def test_mixed_keeps_caller(self, service_bts_env):
        auto = AffectFactory(flaw=FlawFactory(embargoed=False))
        WorkflowLabel.objects.create(flaw=auto.flaw, name=LABEL_AUTO_AFFECTS)
        human = AffectFactory(flaw=FlawFactory(embargoed=False))
        assert _credentials([auto, human]) == CALLER

    def test_manual_triage_keeps_caller(self, service_bts_env):
        affect = AffectFactory(flaw=FlawFactory(embargoed=False))
        WorkflowLabel.objects.create(flaw=affect.flaw, name=LABEL_MANUAL_TRIAGE)
        assert _credentials([affect]) == CALLER

    def test_empty_keeps_caller(self, service_bts_env):
        assert _credentials([]) == CALLER

    def test_missing_service_jira_credentials_raise(self, monkeypatch):
        affect = AffectFactory(flaw=FlawFactory(embargoed=False))
        WorkflowLabel.objects.create(flaw=affect.flaw, name=LABEL_AUTO_AFFECTS)
        monkeypatch.setattr("collectors.bzimport.constants.BZ_API_KEY", SERVICE[0])
        monkeypatch.setattr("apps.taskman.constants.JIRA_AUTH_TOKEN", None)
        monkeypatch.setattr("apps.taskman.constants.JIRA_EMAIL", SERVICE[2])

        with pytest.raises(serializers.ValidationError) as exc_info:
            filing_credentials(
                [affect],
                bz_api_key=CALLER[0],
                jira_token=CALLER[1],
                jira_email=CALLER[2],
                tracker_type=Tracker.TrackerType.JIRA,
            )
        assert "Jira-Api-Key" in exc_info.value.detail

    def test_blank_service_bugzilla_credentials_raise(self, monkeypatch):
        affect = AffectFactory(flaw=FlawFactory(embargoed=False))
        WorkflowLabel.objects.create(flaw=affect.flaw, name=LABEL_AUTO_AFFECTS)
        monkeypatch.setattr("collectors.bzimport.constants.BZ_API_KEY", "")
        monkeypatch.setattr("apps.taskman.constants.JIRA_AUTH_TOKEN", SERVICE[1])
        monkeypatch.setattr("apps.taskman.constants.JIRA_EMAIL", SERVICE[2])

        with pytest.raises(serializers.ValidationError) as exc_info:
            filing_credentials(
                [affect],
                bz_api_key=CALLER[0],
                jira_token=CALLER[1],
                jira_email=CALLER[2],
                tracker_type=Tracker.TrackerType.BUGZILLA,
            )
        assert "Bugzilla-Api-Key" in exc_info.value.detail
