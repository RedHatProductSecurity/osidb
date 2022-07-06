from osidb.helpers import get_env

# Auth
JIRA_SERVER = get_env("JIRA_URL", default="https://issues.redhat.com")
JIRA_TOKEN = get_env("JIRA_AUTH_TOKEN")

# External resources
PRODUCT_DEFINITIONS_URL = (
    get_env("DASHBOARD_URL", "") + "/rest/api/latest/product-definitions"
)

# JIRA-specific
JIRAFFE_AUTO_SYNC = get_env("JIRAFFE_AUTO_SYNC", default="True", is_bool=True)
JIRA_SYNC_INTERVAL = "1m"

# Celery task constants
JIRA_MAX_TRIES = 3
JIRA_SOFT_TIME_LIMIT = 240
JIRA_RATE_LIMIT = get_env("OSIDB_JIRA_RATE_LIMIT", default="8/m")
