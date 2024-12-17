"""
flaw labels collector
"""

from celery.schedules import crontab
from celery.utils.log import get_task_logger
from django.utils import timezone

from collectors.framework.models import collector
from osidb.models import FlawLabel

from .constants import FLAW_LABELS_REPO_BRANCH, FLAW_LABELS_REPO_URL
from .core import fetch_flaw_labels, sync_flaw_labels

logger = get_task_logger(__name__)


# GitLab URL to specific branch
FLAW_LABELS_URL = "/".join(
    (
        FLAW_LABELS_REPO_URL,
        "-",
        "raw",
        FLAW_LABELS_REPO_BRANCH,
        "mapping",
        "flaw_label_mapping.yaml",
    )
)


@collector(
    # Execute this every 3 hours
    crontab=crontab(minute="27", hour="*/3"),
    data_models=[FlawLabel],
)
def flaw_labels_collector(collector_obj) -> None:
    """flaw labels collector"""

    # Fetch raw yaml data from GitLab
    logger.info(f"Fetching Flaw labels from '{FLAW_LABELS_URL}'")
    (context_based, product_family) = fetch_flaw_labels(FLAW_LABELS_URL)

    logger.info(
        (
            f"Fetched {len(context_based)} Context Based labels "
            f"and {len(product_family)} Product Family labels"
        )
    )

    # Sync all flaw labels in a single transaction
    sync_flaw_labels(context_based, product_family)

    collector_obj.store(updated_until_dt=timezone.now())
    logger.info("Flaw labels sync was successful.")
    return f"The run of {collector_obj.name} finished."
