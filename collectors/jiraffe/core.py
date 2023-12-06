from datetime import datetime, timedelta
from typing import List, Tuple

from celery.utils.log import get_task_logger
from django.utils import timezone
from jira import JIRA, Issue
from jira.exceptions import JIRAError

from .constants import JIRA_DT_FMT, JIRA_MAX_CONNECTION_AGE, JIRA_SERVER, JIRA_TOKEN
from .exceptions import NonRecoverableJiraffeException

logger = get_task_logger(__name__)


class JiraConnector:
    """
    Jira connection handler
    """

    _jira_server = JIRA_SERVER
    _jira_token = JIRA_TOKEN

    def __init__(self):
        self._jira_conn = None
        self._jira_conn_timestamp = None

    ###################
    # JIRA CONNECTION #
    ###################
    def _get_jira_connection(self) -> JIRA:
        """
        Returns the JIRA connection object on which to perform queries to the JIRA API.
        """
        options = {
            "server": self._jira_server,
            # avoid the JIRA lib auto-updating
            "check_update": False,
        }
        return JIRA(options, token_auth=self._jira_token, get_server_info=False)

    @property
    def jira_conn(self) -> JIRA:
        """
        Get Jira connection

        Create a new connection if it does not exist. If JIRA_MAX_CONNECTION_AGE is set and the
        connection is older, also create a new connection. Otherwise, reuse already created
        connection.
        """
        if self._jira_conn is None:
            self._jira_conn = self._get_jira_connection()
            self._jira_conn_timestamp = datetime.now()
            logger.info("New Jira connection created, no previous connection")

        elif JIRA_MAX_CONNECTION_AGE is not None:
            connection_age = datetime.now() - self._jira_conn_timestamp
            if connection_age > timedelta(seconds=int(JIRA_MAX_CONNECTION_AGE)):
                self._jira_conn = self._get_jira_connection()
                self._jira_conn_timestamp = datetime.now()
                logger.info(
                    f"New Jira connection created, previous age {connection_age}"
                )

        return self._jira_conn


class JiraQuerier(JiraConnector):
    """
    Jira query handler
    """

    ###########
    # HELPERS #
    ###########

    def datetime2jira_str(self, timestamp: timezone.datetime, inc: bool = False) -> str:
        """
        transform timestamp to expected Jira query string

        note that Jira query does not allow seconds granularity so we have to cut the seconds off
        which brings an interesting issue of dealing with the period borders and we have to extend
        them to the closest minute with respect to whether it is the opening or closing of the period

        param inc
            False cut off the seconds
            True cut off the seconds and add one minute
        """
        if inc:
            # add one minute to the timestamp for closing border
            timestamp = timestamp + timezone.timedelta(minutes=1)

        # we cut off the seconds by the format
        return timestamp.strftime(JIRA_DT_FMT)

    ###################
    # QUERY EXECUTORS #
    ###################

    def create_query(self, query_list: List[Tuple[str, str, str]]) -> str:
        """
        create a query string from the query tuple-list

        where an item is supposed to be one query condition
        in the form (name, operator, value) and we also
        assume that the items are in conjuction form
        """
        query_items = []
        for name, operator, value in query_list:
            query_items.append(f'{name}{operator}"{value}"')
        return " AND ".join(query_items)

    def run_query(self, query_list: List[Tuple[str, str, str]]) -> List[Issue]:
        """
        get Jira issues performing the given query
        """
        return self.jira_conn.search_issues(
            self.create_query(query_list), maxResults=False
        )

    ###################
    # QUERY MODIFIERS #
    ###################

    def query_trackers(
        self, query_list: List[Tuple[str, str, str]]
    ) -> List[Tuple[str, str, str]]:
        """
        update query dictionary to query trackers
        """
        query_list.append(("labels", "=", "SecurityTracking"))
        query_list.append(("type", "=", "Bug"))
        return query_list

    def query_updated(
        self,
        query_list: List[Tuple[str, str, str]],
        updated_after: timezone.datetime,
        updated_before: timezone.datetime,
    ) -> List[Tuple[str, str, str]]:
        """
        update query dictionary to query for updates in the given period
        """
        query_list.append(("updated", ">=", self.datetime2jira_str(updated_after)))
        query_list.append(
            ("updated", "<=", self.datetime2jira_str(updated_before, inc=True))
        )
        return query_list

    ########################
    # SINGLE ISSUE QUERIES #
    ########################

    def get_issue(self, jira_id: str) -> Issue:
        """
        get Jira issue specified by Jira ID
        """
        try:
            return self.jira_conn.issue(jira_id)
        except JIRAError as e:
            if "Issue Does Not Exist" in str(e):
                # restricted access cannot be distinguished
                # from non-existance based on the response
                raise NonRecoverableJiraffeException(
                    "Issue access is restricted or it does not exist"
                )
            # re-raise otherwise
            raise e

    #######################
    # MULTI ISSUE QUERIES #
    #######################

    def get_tracker_period(
        self, updated_after: timezone.datetime, updated_before: timezone.datetime
    ) -> List[Issue]:
        """
        get list of trackers updated during the given period
        """
        query_list = []
        query_list = self.query_trackers(query_list)
        query_list = self.query_updated(query_list, updated_after, updated_before)
        return self.run_query(query_list)
