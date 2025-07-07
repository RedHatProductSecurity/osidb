"""
Jira specific tracker constants
"""
from pydantic_settings import BaseSettings, SettingsConfigDict

from osidb.helpers import get_env

JIRA_SERVER = get_env("JIRA_URL", default="https://issues.redhat.com")
JIRA_EMBARGO_SECURITY_LEVEL_NAME = get_env(
    "JIRA_EMBARGO_SECURITY_LEVEL_NAME", default="Embargoed Security Issue"
)
JIRA_INTERNAL_SECURITY_LEVEL_NAME = get_env(
    "JIRA_INTERNAL_SECURITY_LEVEL_NAME", default="Red Hat Employee"
)
TRACKER_FEEDBACK_FORM_URL = get_env("TRACKER_FEEDBACK_FORM_URL")

# Translate fields as defined in product definitions to the actual Jira field
PS_ADDITIONAL_FIELD_TO_JIRA = {
    "fixVersions": "fixVersions",
    "release_blocker": "customfield_12319743",
    "target_release": "customfield_12311240",
    "target_version": "customfield_12319940",
}


class TrackersAppSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OSIDB_TRACKERS_")

    # whether PURLs should be used for the downstream component field when
    # creating JIRA engineering trackers
    prefer_purls: bool = True
