from osidb.helpers import get_env, get_env_date

# Switch to turn the collector on/off
CVEORG_COLLECTOR_ENABLED = get_env(
    "CVEORG_COLLECTOR_ENABLED", default="True", is_bool=True
)

CVEORG_START_DATE = get_env_date("CVEORG_START_DATE", default="2024-10-01")

CELERY_PVC_PATH = get_env("CELERY_PVC_PATH", default="/opt/app-root/output-files")

KEYWORDS_CHECK_ENABLED = get_env("KEYWORDS_CHECK_ENABLED", default="True", is_bool=True)

CISA_ORG_ID = get_env("CISA_ORG_ID", default="134c704f-9b21-4f2e-91b3-4a467353bcc0")
