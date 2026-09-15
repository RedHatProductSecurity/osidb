"""
Jira tracker query module
"""

import json
import logging
from datetime import datetime

from django.utils import timezone
from jira import JIRAError

from apps.trackers.exceptions import BTSException
from collectors.jiraffe.constants import JIRA_DT_FULL_FMT
from collectors.jiraffe.core import JiraQuerier

from .constants import JIRA_SERVER
from .query import OldTrackerJiraQueryBuilder, TrackerJiraQueryBuilder

logger = logging.getLogger(__name__)

# Jira Cloud sometimes omits fractional seconds
_JIRA_DT_FMTS = (JIRA_DT_FULL_FMT, "%Y-%m-%dT%H:%M:%S%z")


def parse_jira_datetime(value):
    """
    parse a Jira datetime string into an aware datetime
    """
    if not value:
        return None
    for fmt in _JIRA_DT_FMTS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    logger.warning("Unable to parse Jira datetime %r", value)
    return None


def apply_jira_issue_timestamps(tracker, issue):
    """
    copy created/updated timestamps from a Jira issue onto the tracker

    tracker create uses Unix epoch as a placeholder until BTS timestamps exist.
    without this copy OSIM displays 1970-01-01 until a collector later syncs.
    """
    fields = getattr(issue, "fields", None)
    created_dt = parse_jira_datetime(getattr(fields, "created", None))
    updated_dt = parse_jira_datetime(getattr(fields, "updated", None)) or created_dt
    if created_dt is None:
        created_dt = timezone.now()
        logger.warning(
            "Jira issue %s had no parseable created timestamp; using now for tracker %s",
            getattr(issue, "key", None),
            getattr(tracker, "uuid", None),
        )
    tracker.created_dt = created_dt
    tracker.updated_dt = updated_dt or created_dt


class TrackerJiraSaver(JiraQuerier):
    """
    Jira tracker bug save handler
    """

    def __init__(self, tracker, token, email, jira_issuetype=None) -> None:
        """
        Instantiate a new JiraTrackerQuerier object.

        Keyword arguments:
        token -- user token used in every request to Jira
        email -- user email used in every request to Jira
        """
        super().__init__()
        self.tracker = tracker
        self._jira_server = JIRA_SERVER
        self._jira_token = token
        self._jira_email = email
        self._jira_issuetype = jira_issuetype

    def save(self):
        """
        generic save serving as class entry point
        which calls create or update handler to continue
        returns an updated instance (without saving)
        """
        return (
            self.create(self.tracker)
            if not self.tracker.external_system_id
            else self.update(self.tracker)
        )

    def get_builder(self):
        """
        select the Jira query builder for the configured issuetype
        """
        if not self._jira_issuetype:
            return OldTrackerJiraQueryBuilder

        if self._jira_issuetype == "Bug":
            return OldTrackerJiraQueryBuilder
        elif self._jira_issuetype == "Vulnerability":
            return TrackerJiraQueryBuilder
        else:
            raise BTSException(
                f"Unexpected Jira issuetype {self._jira_issuetype} in TrackerJiraSaver"
            )

    def create(self, tracker):
        """
        create a representation of tracker model in Jira
        """
        builder = self.get_builder()
        querybuilder = builder(tracker)
        query = querybuilder.query
        comment = querybuilder.query_comment
        try:
            issue = self.jira_conn.create_issue(fields=query["fields"], prefetch=True)
        except JIRAError as e:
            logger.error(
                "JIRAError during tracker creation: %s | ps_update_stream=%s | ps_module=%s | ps_component=%s | uuid=%s",
                str(e),
                getattr(tracker, "ps_update_stream", None),
                getattr(tracker, "ps_module", None),
                getattr(tracker, "ps_component", None),
                getattr(tracker, "uuid", None),
            )
            raise
        tracker.external_system_id = issue.key
        apply_jira_issue_timestamps(tracker, issue)
        if comment:
            self.create_comment(
                issue_key=issue.key,
                body=comment,
            )
        for reference in tracker.references:
            self.add_link(
                issue_key=issue.key,
                url=reference.url,
                title=reference.description,
            )

        return tracker

    def update(self, tracker):
        """
        update an existing representation of tracker model in Jira
        """
        builder = self.get_builder()(tracker)

        if tracker.is_closed:
            if isinstance(builder, TrackerJiraQueryBuilder):
                builder.generate_only_embargo_and_security_level()
            else:
                builder.generate_only_security()

        query = builder.query

        url = f"{self.jira_conn._get_url('issue')}/{query['key']}"
        self.jira_conn._session.put(url, json.dumps(query))
        return tracker
