from osidb.helpers import get_env

TASKMAN_API_VERSION = "v1"

JIRA_AUTH_TOKEN = get_env("JIRA_AUTH_TOKEN")
JIRA_TASKMAN_URL = get_env("JIRA_TASKMAN_URL")
JIRA_TASKMAN_PROJECT_KEY = get_env("JIRA_TASKMAN_PROJECT_KEY", default="OSIM")
HTTPS_TASKMAN_PROXY = get_env("HTTPS_TASKMAN_PROXY")
JIRA_TASKMAN_AUTO_SYNC_FLAW = get_env(
    "JIRA_TASKMAN_AUTO_SYNC_FLAW", default="0", is_bool=True
)

SYNC_REQUIRED_FIELDS = [
    "cve_id",
    "impact",
    "is_embargoed",
    "owner",
    "team_id",
    "workflow_state",
]
