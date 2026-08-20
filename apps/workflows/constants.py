"""
Workflows constants
"""

from osidb.helpers import get_env_date

WORKFLOWS_API_VERSION_V1: str = "v1"
WORKFLOW_DIR = "apps/workflows/workflows"

# Flaws created before this date that are already in the DONE workflow state
# are excluded from automatic workflow re-classification. When the automation
# was introduced the DONE criteria differed from the historical ones, so
# re-classifying old flaws reopened them and confused people. An empty value
# means no time restriction - all flaws are subject to re-classification.
WORKFLOW_RECLASSIFICATION_START_DATE = get_env_date(
    "OSIDB_WORKFLOW_RECLASSIFICATION_START_DATE"
)
