from osidb.helpers import get_env

TASKMAN_API_VERSION = "v1"

JIRA_AUTH_TOKEN = get_env("JIRA_AUTH_TOKEN")
# The length of summary in a Jira task is restricted to 255
JIRA_SUMMARY_MAX_LENGTH = 255
JIRA_STORY_ISSUE_TYPE_ID = get_env("JIRA_STORY_ISSUE_TYPE_ID")
JIRA_TASKMAN_URL = get_env("JIRA_TASKMAN_URL", default="https://issues.redhat.com")
JIRA_TASKMAN_PROJECT_ID = get_env("JIRA_TASKMAN_PROJECT_ID")
JIRA_TASKMAN_PROJECT_KEY = get_env("JIRA_TASKMAN_PROJECT_KEY", default="OSIM")
HTTPS_JIRA_PROXY = get_env("HTTPS_JIRA_PROXY")
JIRA_TASKMAN_AUTO_SYNC_FLAW = get_env(
    "JIRA_TASKMAN_AUTO_SYNC_FLAW", default="0", is_bool=True
)
JIRA_TASKMAN_ASYNCHRONOUS_SYNC = get_env(
    "JIRA_TASKMAN_ASYNCHRONOUS_SYNC", default="False", is_bool=True
)

SYNC_REQUIRED_FIELDS = [
    "cve_id",
    "impact",
    "is_embargoed",
    "owner",
    "team_id",
]
TRANSITION_REQUIRED_FIELDS = [
    "workflow_state",
]
