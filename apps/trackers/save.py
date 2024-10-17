"""
common tracker save funtionality
"""
from osidb.models.flaw.flaw import Flaw
from osidb.models.tracker import Tracker

from .bugzilla.save import TrackerBugzillaSaver
from .exceptions import BTSException, UnsupportedTrackerError
from .jira.save import TrackerJiraSaver


class TrackerSaver:
    """
    common tracker save handler
    provides the specific sub-handler
    """

    def __new__(cls, tracker, bz_api_key=None, jira_token=None, jira_issuetype=None):
        """
        detect and return the correct saver
        assuming that all prerequisites are met
        """
        # we do not support tracker filing for the old multi-CVE flaws
        for affect in tracker.affects.all():
            if (
                affect.flaw.bz_id
                and Flaw.objects.filter(meta_attr__bz_id=affect.flaw.bz_id).count() > 1
            ):
                raise UnsupportedTrackerError(
                    "Creating trackers for flaws with multiple CVEs is not supported"
                )

        if tracker.type == Tracker.TrackerType.BUGZILLA:
            assert bz_api_key, "Bugzilla API key not provided"
            return TrackerBugzillaSaver(tracker, bz_api_key)

        if tracker.type == Tracker.TrackerType.JIRA:
            assert jira_token, "Jira access token not provided"
            return TrackerJiraSaver(tracker, jira_token, jira_issuetype)

        # we should never get here
        raise BTSException("Unknown BTS")
