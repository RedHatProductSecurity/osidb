"""
Jira tracker query module
"""
import logging

from django.db import transaction
from jira.exceptions import JIRAError
from rest_framework.response import Response

from collectors.jiraffe.core import JiraQuerier
from osidb.models import Affect, PsUpdateStream, Tracker

from .constants import JIRA_SERVER
from .core import JiraTracker

logger = logging.getLogger(__name__)


class JiraTrackerQuerier(JiraQuerier):
    """
    Jira query handler for tracker management.
    This class encapsulates calls for Jira doing validations
    and its methods return data requested with HTTP status code
    """

    def __init__(self, token) -> None:
        """
        Instantiate a new JiraTrackerQuerier object.

        Keyword arguments:
        token -- user token used in every request to Jira
        """
        self._jira_server = JIRA_SERVER
        self._jira_token = token

    def get_bts_tracker(self, bts_id):
        """get Jira tracker given its string key or integer id"""
        try:
            return Response(data=self.jira_conn.issue(bts_id).raw, status=200)
        except JIRAError as e:
            return Response(data=e.response.json(), status=e.status_code)

    def create_bts_affect_tracker(
        self, affect: Affect, tracked_streams: list[PsUpdateStream]
    ):
        """
        Generates a tracker in BTS given an Affect.
        If multiples streams is given creates one tracker per stream.
        """
        stream_names = [stream.name for stream in tracked_streams]
        existing_trackers = affect.trackers.filter(
            ps_update_stream__in=stream_names
        ).values_list("ps_update_stream", flat=True)
        if existing_trackers:
            existing_trackers = ",".join(existing_trackers)
            return Response(
                data=f"Affect already have trackers created for stream(s) [{existing_trackers}].",
                status=409,
            )

        # creates a list of trackers to be generated in BTS
        bts_trackers = []

        for stream in tracked_streams:
            bts_trackers.append(
                JiraTracker(
                    flaw=affect.flaw,
                    affect=affect,
                    stream=stream,
                )
            )
        # submits a list of trackers/Jira issues to be created in bulk
        try:
            bulk_issues = []
            for bts_tracker in bts_trackers:
                bulk_issues.append(bts_tracker.generate_bts_object()["fields"])

            response = self.jira_conn.create_issues(bulk_issues, prefetch=True)
        except JIRAError as e:
            return Response(data=e.response.json(), status=e.status_code)

        # creates in OSIDB the equivalent entity for the created BTS trackers
        issues = [created["issue"] for created in response]
        try:
            with transaction.atomic():
                i = 0
                while i < len(response):
                    issue = issues[i].raw
                    bts_tracker = bts_trackers[i]
                    tracker = Tracker(
                        type=Tracker.TrackerType.JIRA,
                        external_system_id=issue["key"],
                        status=issue["fields"]["status"]["name"],
                        ps_update_stream=bts_tracker._stream.name,
                        acl_read=affect.acl_read,
                        acl_write=affect.acl_write,
                    )
                    tracker.save()
                    tracker.affects.add(bts_tracker._affect)
                    i += 1
            return Response(data=response, status=201)
        except Exception as e:
            tracker_bts_keys = ",".join([issue.raw["key"] for issue in issues])
            return Response(
                data=f"Tracker(s) [{tracker_bts_keys}] created in Jira but not in OSIDB. {e}",
                status=409,
            )
