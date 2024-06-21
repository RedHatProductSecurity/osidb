import re

from osidb.helpers import get_env

# Auth
JIRA_SERVER = get_env("JIRA_URL", default="https://issues.redhat.com")
JIRA_TOKEN = get_env("JIRA_AUTH_TOKEN")
HTTPS_PROXY = get_env("HTTPS_TASKMAN_PROXY")
JIRA_TASKMAN_PROJECT_KEY = get_env("JIRA_TASKMAN_PROJECT_KEY", default="OSIM")

# Jira datetime format string
JIRA_DT_FMT = "%Y-%m-%d %H:%M"

# Maximum age of connection to Jira in seconds, recommended value is 60
JIRA_MAX_CONNECTION_AGE = get_env("JIRA_MAX_CONNECTION_AGE")

# Jira label containing Bugzilla ID
JIRA_BZ_ID_LABEL_RE = re.compile(r"flaw:bz#(\d+)")

# Switches to turn each collector on/off
JIRA_TRACKER_COLLECTOR_ENABLED = get_env(
    "JIRA_TRACKER_COLLECTOR_ENABLED", default="True", is_bool=True
)
JIRA_METADATA_COLLECTOR_ENABLED = get_env(
    "JIRA_METADATA_COLLECTOR_ENABLED", default="True", is_bool=True
)
