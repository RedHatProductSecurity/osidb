"""
product definitions collector
"""

from celery.schedules import crontab
from celery.utils.log import get_task_logger
from django.utils import timezone

from collectors.framework.models import collector
from osidb.models import (
    CompliancePriority,
    ContractPriority,
    SpecialConsiderationPackage,
    UbiPackage,
)

from .constants import PS_CONSTANTS_REPO_BRANCH, PS_CONSTANTS_REPO_URL
from .core import (
    fetch_ps_constants,
    sync_compliance_priority,
    sync_contract_priority,
    sync_sla_policies,
    sync_special_consideration_packages,
    sync_ubi_packages,
)

logger = get_task_logger(__name__)


# GitLab URL to specific branch
PS_CONSTANTS_BASE_URL = "/".join(
    (
        PS_CONSTANTS_REPO_URL,
        "-",
        "raw",
        PS_CONSTANTS_REPO_BRANCH,
        "data",
    )
)


@collector(
    # Execute this every 6 hours
    # TODO: crontab seems to be not sufficient as a scheduler here
    # since it is only capable of running the job at every fixed third hour
    # eg. 3:00,8:00,etc. and thus there exist a scenario in which
    # the OSIDB is run lets say 3:01 and this job will be scheduled on 8:49
    # which is really not what we want, since there may be other collectors
    # depending on this one, odd minute number was chosen in order to not have multiple
    # tasks running at the same time
    # TODO: Use django_celery_beat which has PeriodicTask with IntervalSchedule
    #  What we use here is equivalent to PeriodicTask with CrontabSchedule
    crontab=crontab(minute="49", hour="*/5"),
    data_models=[
        CompliancePriority,
        ContractPriority,
        SpecialConsiderationPackage,
        UbiPackage,
    ],
)
def ps_constants_collector(collector_obj) -> str:
    """ps constants collector"""

    # Fetch raw yml data from GitLab
    url = "/".join((PS_CONSTANTS_BASE_URL, "compliance_priority.yml"))
    logger.info(f"Fetching PS Constants (compliance priority) from '{url}'")
    compliance_priority = fetch_ps_constants(url)

    url = "/".join((PS_CONSTANTS_BASE_URL, "contract_priority.yml"))
    logger.info(f"Fetching PS Constants (contract priority) from '{url}'")
    contract_priority = fetch_ps_constants(url)

    url = "/".join((PS_CONSTANTS_BASE_URL, "ubi_packages.yml"))
    logger.info(f"Fetching PS Constants (Ubi Packages) from '{url}'")
    ubi_packages = fetch_ps_constants(url)

    url = "/".join((PS_CONSTANTS_BASE_URL, "special_consideration_packages.yml"))
    logger.info(f"Fetching PS Constants (Special Consideration Packages) from '{url}'")
    sc_packages = fetch_ps_constants(url)

    url = "/".join((PS_CONSTANTS_BASE_URL, "sla_policies.yml"))
    logger.info(f"Fetching PS Constants (SLA Policies) from '{url}'")
    sla_policies = fetch_ps_constants(url, multi=True)

    logger.info(
        (
            f"Fetched ubi packages for {len(ubi_packages)} RHEL major versions "
            f"and {len(sc_packages)} special consideration packages "
            f"and compliance priority data. "
            f"Going to sync."
        )
    )

    sync_compliance_priority(compliance_priority)
    sync_contract_priority(contract_priority)
    sync_ubi_packages(ubi_packages)
    sync_special_consideration_packages(sc_packages)
    sync_sla_policies(sla_policies)

    collector_obj.store(updated_until_dt=timezone.now())
    logger.info("PS Constants sync was successful.")
    return f"The run of {collector_obj.name} finished."
