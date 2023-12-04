from osidb.helpers import get_env

# Auth
JIRA_SERVER = get_env("JIRA_URL", default="https://issues.redhat.com")
JIRA_TOKEN = get_env("JIRA_AUTH_TOKEN")
HTTPS_PROXY = get_env("HTTPS_TASKMAN_PROXY")

# Jira datetime format string
JIRA_DT_FMT = "%Y-%m-%d %H:%M"

# Maximum age of connection to Jira in seconds, recommended value is 60
JIRA_MAX_CONNECTION_AGE = get_env("JIRA_MAX_CONNECTION_AGE")
