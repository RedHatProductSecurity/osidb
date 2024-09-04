from osidb.helpers import get_env

# Switch to turn the collector on/off
CVEORG_COLLECTOR_ENABLED = get_env(
    "CVEORG_COLLECTOR_ENABLED", default="False", is_bool=True
)

CELERY_PVC_PATH = get_env("CELERY_PVC_PATH", default="/opt/app-root/output-files")
