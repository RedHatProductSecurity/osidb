from osidb.helpers import get_env

TASKMAN_API_VERSION = "v1"

JIRA_TASKMAN_URL = get_env(
    "JIRA_TASKMAN_URL", default="https://issues.stage.redhat.com"
)
JIRA_TASKMAN_PROJECT_KEY = get_env("JIRA_TASKMAN_PROJECT_KEY", default="OSIM")
HTTPS_PROXY = get_env("HTTPS_PROXY", default="http://squid.corp.redhat.com:3128")
