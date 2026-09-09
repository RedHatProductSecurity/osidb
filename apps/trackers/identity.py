"""Choose BTS credentials when filing trackers for auto-analyzed flaws."""

from rest_framework import serializers

from apps.ace.constants import LABEL_AUTO_AFFECTS
from osidb.models import Tracker


def is_auto_analyzed_flaw(flaw) -> bool:
    """True when ACE (in-process or affect-creator) analyzed this flaw."""
    if flaw.has_label(LABEL_AUTO_AFFECTS):
        return True
    return flaw.affects.filter(created_by="AffectCreationEngine").exists()


def all_linked_flaws_auto_analyzed(affects) -> bool:
    """True when every flaw linked through these affects was auto-analyzed."""
    if not affects:
        return False
    return all(is_auto_analyzed_flaw(affect.flaw) for affect in affects)


def _ensure_service_credentials(tracker_type, bz_api_key, jira_token, jira_email):
    """Reject auto-filing when the OSIDB service account is not configured."""
    errors = {}
    needs_bugzilla = tracker_type in (None, Tracker.TrackerType.BUGZILLA)
    needs_jira = tracker_type in (None, Tracker.TrackerType.JIRA)

    if needs_bugzilla and not bz_api_key:
        errors["Bugzilla-Api-Key"] = (
            "OSIDB service Bugzilla credentials are not configured "
            "(BZIMPORT_BZ_API_KEY)."
        )
    if needs_jira and (not jira_token or not jira_email):
        errors["Jira-Api-Key"] = (
            "OSIDB service Jira credentials are not configured "
            "(JIRA_AUTH_TOKEN, JIRA_EMAIL)."
        )
    if errors:
        raise serializers.ValidationError(errors)


def filing_credentials(
    affects, *, bz_api_key, jira_token, jira_email, tracker_type=None
):
    """
    Return BTS credentials for tracker create.

    Auto-analyzed flaws file as the OSIDB service account so that account is
    the Jira/Bugzilla reporter. Mixed or human-analyzed flaws keep the caller.
    """
    if not all_linked_flaws_auto_analyzed(affects):
        return bz_api_key, jira_token, jira_email

    from apps.taskman.constants import JIRA_AUTH_TOKEN, JIRA_EMAIL
    from collectors.bzimport.constants import BZ_API_KEY

    _ensure_service_credentials(tracker_type, BZ_API_KEY, JIRA_AUTH_TOKEN, JIRA_EMAIL)
    return BZ_API_KEY, JIRA_AUTH_TOKEN, JIRA_EMAIL
