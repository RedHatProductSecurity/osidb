from osidb.helpers import get_env

# Auth
JIRA_SERVER = get_env("JIRA_URL", default="https://issues.redhat.com")
JIRA_TOKEN = get_env("JIRA_AUTH_TOKEN")

# Jira datetime format string
JIRA_DT_FMT = "%Y-%m-%d %H:%M"
