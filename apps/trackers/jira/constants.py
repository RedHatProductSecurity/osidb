"""
Jira specific tracker constants
"""
from osidb.helpers import get_env

JIRA_SERVER = get_env("JIRA_URL", default="https://issues.redhat.com")
JIRA_EMBARGO_SECURITY_LEVEL_NAME = get_env(
    "JIRA_EMBARGO_SECURITY_LEVEL_NAME", default="Embargoed Security Issue"
)

# Translate additional fields as defined in product definitions to the actual Jira field
PS_ADDITIONAL_FIELD_TO_JIRA = {
    "fixVersions": "fixVersions",
    "release_blocker": "customfield_12319743",
}
