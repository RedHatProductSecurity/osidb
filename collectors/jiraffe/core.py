import json
from functools import cache
from typing import Any, Union
from uuid import UUID

import requests
from jira import JIRA, Issue

from osidb.models import Affect, Tracker

from ..utils import tracker_parse_update_stream_component
from .constants import JIRA_SERVER, JIRA_TOKEN, PRODUCT_DEFINITIONS_URL


class JiraQuerier:
    """Jira query handler"""

    ###################
    # JIRA CONNECTION #
    ###################

    @staticmethod
    @cache
    def _get_jira_connection() -> JIRA:
        """
        Returns the JIRA connection object on which to perform queries to the JIRA API.
        """
        options = {
            "server": JIRA_SERVER,
            # avoid the JIRA lib auto-updating
            "check_update": False,
        }
        return JIRA(options, token_auth=JIRA_TOKEN, get_server_info=False)

    @property
    def jira_conn(self) -> JIRA:
        return self._get_jira_connection()

    ########################
    # SINGLE ISSUE QUERIES #
    ########################

    def get_issue(self, jira_id):
        """get Jira issue"""
        return self.jira_conn.issue(jira_id)


@cache
def get_jira_modules() -> dict:
    """
    Returns a dict with all ps_modules/ps_components tracked in JIRA.
    """
    # TODO: need a proper/generic solution that provides product definitions in a reliable
    # and efficient way, as it stands this will never be updated in long-running OSIDB instances
    response = requests.get(PRODUCT_DEFINITIONS_URL)
    if not response.ok:
        return {}
    data = response.json()
    modules = data["ps_modules"]
    return {
        key: value for key, value in modules.items() if value["bts"]["name"] == "jboss"
    }


def find_jira_trackers(affect: Affect) -> list[Issue]:
    """
    Finds JIRA trackers pertaining to a given affect.
    """
    jira_modules = get_jira_modules()
    module = jira_modules.get(affect.ps_module)
    if module is None:
        return []

    conn = JiraQuerier().jira_conn
    jira_project = module["bts"]["key"]
    jql_query = f'PROJECT={jira_project} \
                AND labels="{affect.flaw and affect.flaw.cve_id}" \
                AND labels="pscomponent:{affect.ps_component}" \
                AND labels="SecurityTracking" \
                AND type="Bug"'
    return conn.search_issues(jql_query, maxResults=False)


def get_field_attr(issue, field, attr):
    """field value getter helper"""
    if hasattr(issue.fields, field):
        if hasattr(getattr(issue.fields, field), attr):
            return getattr(getattr(issue.fields, field), attr)

    return None


def upsert_trackers(affect: Affect, dry_run=False) -> None:
    """
    Creates or updates an affect's trackers.
    """
    issues = find_jira_trackers(affect)
    for issue in issues:
        tracker = Tracker.objects.create_tracker(
            affect=affect,
            external_system_id=issue.key,
            _type=Tracker.TrackerType.JIRA,
            status=get_field_attr(issue, "status", "name"),
            resolution=get_field_attr(issue, "resolution", "name"),
            ps_update_stream=tracker_parse_update_stream_component(
                issue.fields.summary
            )[0],
            acl_read=affect.acl_read,
            acl_write=affect.acl_write,
            # since JIRA status:resolution is wild west keep the raw values as metadata
            # we may reconsider this after OJA value scheme standardization
            meta_attr={
                # raw retrieves the value as a python dict, which is json-serializable
                # NOTE: this would be less of a headache if we used a JSONField instead
                # WARNING: defensive programming here, it is possible that the value of a
                # field is not always a Field object, it can be None
                "owner": get_field_attr(issue, "assignee", "displayName"),
                # QE Assignee corresponds to customfield_12316243
                # in RH Jira which is a field of schema type user
                "qe_owner": get_field_attr(
                    issue, "customfield_12316243", "displayName"
                ),
                "ps_module": affect.ps_module,
                "ps_component": affect.ps_component,
                "status": json.dumps(issue.fields.status and issue.fields.status.raw),
                "resolution": json.dumps(
                    issue.fields.resolution and issue.fields.resolution.raw
                ),
            },
        )
        if not dry_run:
            tracker.save()
            tracker.affects.add(affect)
    if not dry_run:
        affect.save()


def get_affects_to_sync(interval: str) -> Union[tuple[UUID], tuple[Any]]:
    """
    Fetches uuids for Affects that may need a state/resolution sync
    """
    conn = JiraQuerier().jira_conn
    jql_query = f'labels="SecurityTracking" \
                AND type="Bug" \
                AND updated >= "-{interval}"'
    issues = conn.search_issues(jql_query, maxResults=False)

    affect_uuids_to_sync = set()
    for issue in issues:
        # kinda redundant to filter by key AND type but better safe than sorry ?
        trackers = Tracker.objects.filter(
            external_system_id=issue.key, type=Tracker.TrackerType.JIRA
        )
        affect_uuids_to_sync |= {tracker.affect.uuid for tracker in trackers}
    return tuple(affect_uuids_to_sync)
