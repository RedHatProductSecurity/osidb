import re

from osidb.helpers import get_env

# Auth
JIRA_SERVER = get_env("JIRA_URL", default="https://uat-2-2-redhat.atlassian.net")
JIRA_TOKEN = get_env("JIRA_AUTH_TOKEN")
JIRA_EMAIL = get_env("JIRA_EMAIL")
HTTPS_PROXY = get_env("HTTPS_JIRA_PROXY")
JIRA_TASKMAN_PROJECT_KEY = get_env("JIRA_TASKMAN_PROJECT_KEY", default="OSIM")

# Jira datetime format string
JIRA_DT_FMT = "%Y-%m-%d %H:%M"

# Jira datetime full format string
JIRA_DT_FULL_FMT = "%Y-%m-%dT%H:%M:%S.%f%z"

# Maximum age of connection to Jira in seconds, recommended value is 60
JIRA_MAX_CONNECTION_AGE = get_env("JIRA_MAX_CONNECTION_AGE")

# Jira label containing Bugzilla ID
JIRA_BZ_ID_LABEL_RE = re.compile(r"flaw:bz#(\d+)")

# Switches to turn each collector on/off
JIRA_TASK_COLLECTOR_ENABLED = get_env(
    "JIRA_TASK_COLLECTOR_ENABLED", default="True", is_bool=True
)
JIRA_TRACKER_COLLECTOR_ENABLED = get_env(
    "JIRA_TRACKER_COLLECTOR_ENABLED", default="True", is_bool=True
)
JIRA_METADATA_COLLECTOR_ENABLED = get_env(
    "JIRA_METADATA_COLLECTOR_ENABLED", default="True", is_bool=True
)

TASK_CHANGELOG_FIELD_MAPPING = {
    "assignee": ["owner"],
    "status": ["workflow_name", "workflow_state"],
    "resolution": ["workflow_name", "workflow_state"],
}
