"""
product definitions collector
"""
from celery.schedules import crontab
from celery.utils.log import get_task_logger
from django.utils import timezone

from collectors.framework.models import collector
from osidb.models import PsContact, PsModule, PsProduct, PsUpdateStream

from .core import (
    PRODUCT_DEFINITIONS_URL,
    fetch_product_definitions,
    sanitize_product_definitions,
    sync_ps_contacts,
    sync_ps_products_modules,
    sync_ps_update_streams,
)

logger = get_task_logger(__name__)


@collector(
    # Execute this every 3 hours
    # TODO: crontab seems to be not sufficient as a scheduler here
    # since it is only capable of running the job at every fixed third hour
    # eg. 3:00,6:00,9:00,etc. and thus there exist a scenario in which
    # the OSIDB is run lets say 3:01 and this job will be scheduled on 6:00
    # which is really not what we want, since there may be other collectors
    # depending on this one
    # TODO: Use django_celery_beat which has PeriodicTask with IntervalSchedule
    #  What we use here is equivalent to PeriodicTask with CrontabSchedule
    crontab=crontab(minute="0", hour="*/3"),
    data_models=[PsContact, PsModule, PsProduct, PsUpdateStream],
)
def product_definitions_collector(collector_obj) -> None:
    """product definitions collector"""

    # Fetch raw json data from GitLab
    logger.info(f"Fetching Product Definitions from '{PRODUCT_DEFINITIONS_URL}'")
    raw_data = fetch_product_definitions()

    (
        ps_products,
        ps_modules,
        ps_update_streams,
        ps_contacts,
    ) = sanitize_product_definitions(raw_data)

    logger.info(
        (
            f"Fetched {len(ps_products)} PS Products, {len(ps_modules)} PS Modules, "
            f"{len(ps_update_streams)} PS Update Streams and "
            f"{len(ps_contacts)} PS Contacts, going to sync."
        )
    )

    sync_ps_contacts(ps_contacts)
    sync_ps_update_streams(ps_update_streams)
    # PS Products and Modules need to be synced together
    # because every Product holds information about related
    # Modules, but from Module there is no way of telling
    # to which Product it relates to
    sync_ps_products_modules(ps_products, ps_modules)

    collector_obj.store(updated_until_dt=timezone.now())
    logger.info("Product Definitions sync was successful.")
    return f"The run of {collector_obj.name} finished."
