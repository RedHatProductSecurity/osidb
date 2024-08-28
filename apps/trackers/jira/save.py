"""
Jira tracker query module
"""
import json
import logging

from apps.taskman.service import JiraTaskmanQuerier
from collectors.jiraffe.core import JiraQuerier

from .constants import JIRA_SERVER
from .query import OldTrackerJiraQueryBuilder

logger = logging.getLogger(__name__)


class TrackerJiraSaver(JiraQuerier):
    """
    Jira tracker bug save handler
    """

    def __init__(self, tracker, token) -> None:
        """
        Instantiate a new JiraTrackerQuerier object.

        Keyword arguments:
        token -- user token used in every request to Jira
        """
        super().__init__()
        self.tracker = tracker
        self._jira_server = JIRA_SERVER
        self._jira_token = token

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

    def create(self, tracker):
        """
        create a representation of tracker model in Jira
        """
        querybuilder = OldTrackerJiraQueryBuilder(tracker)
        query = querybuilder.query
        comment = querybuilder.query_comment
        issue = self.jira_conn.create_issue(fields=query["fields"], prefetch=True)
        tracker.external_system_id = issue.key
        if comment:
            JiraTaskmanQuerier(token=self._jira_token).create_comment(
                issue_key=issue.key,
                body=comment,
            )
        return tracker

    def update(self, tracker):
        """
        update an existing representation of tracker model in Jira
        """
        query = OldTrackerJiraQueryBuilder(tracker).query
        url = f"{self.jira_conn._get_url('issue')}/{query['key']}"
        self.jira_conn._session.put(url, json.dumps(query))
        return tracker
