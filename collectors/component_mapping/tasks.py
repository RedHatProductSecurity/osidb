from celery.schedules import crontab
from celery.utils.log import get_task_logger
from django.utils import timezone

from collectors.framework.models import collector

from .core import (
    COMPONENT_MAPPING_URL,
    fetch_component_mapping,
    sync_component_mapping,
)
from .models import (
    AmbiguousNpmPackage,
    BlocklistEntry,
    ComponentMapEntry,
    CrossEcosystemName,
    RejectedComponent,
    SemiStrictReviewEntry,
    StrictNpmPackage,
    StrictPackage,
    VerifiedMapping,
)

logger = get_task_logger(__name__)


@collector(
    crontab=crontab(minute="30", hour="*/6"),
    data_models=[
        BlocklistEntry,
        ComponentMapEntry,
        StrictPackage,
        StrictNpmPackage,
        AmbiguousNpmPackage,
        CrossEcosystemName,
        VerifiedMapping,
        SemiStrictReviewEntry,
        RejectedComponent,
    ],
)
def component_mapping_collector(collector_obj) -> str:
    logger.info("Fetching component mapping from '%s'", COMPONENT_MAPPING_URL)
    data = fetch_component_mapping()

    counts = sync_component_mapping(data)
    logger.info(
        "Component mapping sync complete: %s",
        ", ".join(f"{k}={v}" for k, v in counts.items()),
    )

    collector_obj.store(updated_until_dt=timezone.now())
    return f"The run of {collector_obj.name} finished."
