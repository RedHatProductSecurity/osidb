import re

from pydantic_settings import BaseSettings, SettingsConfigDict

from osidb.helpers import get_env

# Auth
JIRA_SERVER = get_env("JIRA_URL", default="https://redhat.atlassian.net")
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

JIRA_METADATA_COLLECTOR_ENABLED = get_env(
    "JIRA_METADATA_COLLECTOR_ENABLED", default="True", is_bool=True
)


class JiraTrackerCollectorSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="JIRA_TRACKER_COLLECTOR_")

    enabled: bool = True
    overlap_seconds: int = 0


jira_collector_settings = JiraTrackerCollectorSettings()
