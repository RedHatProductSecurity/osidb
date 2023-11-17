from datetime import timedelta

from osidb.helpers import get_env

# Auth
JIRA_SERVER = get_env("JIRA_URL", default="https://issues.redhat.com")
JIRA_TOKEN = get_env("JIRA_AUTH_TOKEN")
HTTPS_PROXY = get_env("HTTPS_TASKMAN_PROXY")

# Create new connection when its age is higher than specified value. Based on testing, idle
# connection is dropped after ~10 minutes.
JIRA_MAX_CONNECTION_AGE = timedelta(minutes=1)

# Jira datetime format string
JIRA_DT_FMT = "%Y-%m-%d %H:%M"
