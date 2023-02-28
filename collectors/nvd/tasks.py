"""
nvd collector
"""
from celery.schedules import crontab
from celery.utils.log import get_task_logger
from django.conf import settings
from django.utils import timezone

from collectors.bzimport.collectors import FlawCollector, NVDQuerier
from collectors.framework.models import collector
from osidb.core import set_user_acls
from osidb.models import Flaw

logger = get_task_logger(__name__)


# TODO: This is a temporary solution for NVD CVSS collecting. It is run
# once a day during midnight to fetch all the NVD CVSS changes. This should
# be eventually replaced by a proper collector with more effective update logic.
@collector(
    crontab=crontab(minute="0", hour="0"),
)
def nvd_collector(collector_obj) -> None:
    """nvd collector"""

    # set osidb.acl to be able to CRUD database properly and essentially bypass ACLs as
    # celery workers should be able to read/write any information in order to fulfill their jobs
    set_user_acls(
        settings.PUBLIC_READ_GROUPS
        + [
            settings.PUBLIC_WRITE_GROUP,
            settings.EMBARGO_READ_GROUP,
            settings.EMBARGO_WRITE_GROUP,
        ]
    )

    logger.info("Fetching NVD CVSS")
    start_dt = timezone.now()
    nvd_cvss = NVDQuerier.nvd_cvss()

    desync = []
    for cve, data in nvd_cvss.items():
        flaw = Flaw.objects.filter(cve_id=cve).first()
        if (
            flaw
            and (flaw.nvd_cvss3 or data["cvss3"])
            and flaw.nvd_cvss3 != data["cvss3"]
        ):
            desync.append(cve)

    logger.info(
        f"Following CVEs have NVD CVSS desynced, going to sync: {', '.join(desync)}"
        if desync
        else "No CVEs with desynced NVD CVSS."
    )
    fc = FlawCollector()
    for cve in desync:
        fc.sync_flaw(Flaw.objects.filter(cve_id=cve).first().meta_attr["bz_id"])

    collector_obj.store(updated_until_dt=start_dt)

    msg = f"{collector_obj.name} is updated until {start_dt}."
    msg += f"CVEs synced: {', '.join(desync)}" if desync else ""

    logger.info("NVD sync was successful.")
    return msg
