"""
common tracker save funtionality
"""
from osidb.models import Tracker

from .bugzilla.save import TrackerBugzillaSaver
from .exceptions import BTSException


class TrackerSaver:
    """
    common tracker save handler
    provides the specific sub-handler
    """

    # TODO Jira part
    def __new__(cls, tracker, bz_api_key=None):
        """
        detect and return the correct saver
        assuming that all prerequisites are met
        """
        if tracker.type == Tracker.TrackerType.BUGZILLA:
            assert bz_api_key, "Bugzilla API key not provided"
            return TrackerBugzillaSaver(tracker, bz_api_key)

        if tracker.type == Tracker.TrackerType.JIRA:
            raise NotImplementedError

        # we should never get here
        raise BTSException("Unknown BTS")
