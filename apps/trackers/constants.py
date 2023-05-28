from osidb.helpers import get_env

TRACKER_API_VERSION = "v1"

JIRA_SERVER = get_env("JIRA_URL", default="https://issues.redhat.com")
