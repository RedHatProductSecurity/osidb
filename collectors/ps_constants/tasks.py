"""
product definitions collector
"""

from celery.schedules import crontab
from celery.utils.log import get_task_logger
from django.utils import timezone

from collectors.framework.models import collector
from osidb.models import SpecialConsiderationPackage, UbiPackage

from .constants import PS_CONSTANTS_REPO_BRANCH, PS_CONSTANTS_REPO_URL
from .core import (
    fetch_ps_constants,
    sync_jira_bug_issuetype,
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


def collect_step_1_fetch():
    # Fetch raw yml data from GitLab
    url = "/".join((PS_CONSTANTS_BASE_URL, "ubi_packages.yml"))
    logger.info(f"Fetching PS Constants (Ubi Packages) from '{url}'")
    ubi_packages = fetch_ps_constants(url)

    url = "/".join((PS_CONSTANTS_BASE_URL, "special_consideration_packages.yml"))
    logger.info(f"Fetching PS Constants (Special Consideration Packages) from '{url}'")
    sc_packages = fetch_ps_constants(url)

    url = "/".join((PS_CONSTANTS_BASE_URL, "sla_policies.yml"))
    logger.info(f"Fetching PS Constants (SLA Policies) from '{url}'")
    sla_policies = fetch_ps_constants(url, multi=True)

    url = "/".join((PS_CONSTANTS_BASE_URL, "jira_bug_issuetype.yml"))
    logger.info(f"Fetching PS Constants (Jira Bug issuetype) from '{url}'")
    jira_bug_issuetype = fetch_ps_constants(url)

    return (
        ubi_packages,
        sc_packages,
        sla_policies,
        jira_bug_issuetype,
    )


def collect_step_2_sync(
    ubi_packages,
    sc_packages,
    sla_policies,
    jira_bug_issuetype,
):
    sync_ubi_packages(ubi_packages)
    sync_special_consideration_packages(sc_packages)
    sync_sla_policies(sla_policies)
    sync_jira_bug_issuetype(jira_bug_issuetype)


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
        SpecialConsiderationPackage,
        UbiPackage,
    ],
)
def ps_constants_collector(collector_obj) -> str:
    """ps constants collector"""

    (
        ubi_packages,
        sc_packages,
        sla_policies,
        jira_bug_issuetype,
    ) = collect_step_1_fetch()

    logger.info(
        (
            f"Fetched ubi packages for {len(ubi_packages)} RHEL major versions "
            f"and {len(sc_packages)} special consideration packages data."
            f"Going to sync."
        )
    )

    collect_step_2_sync(
        ubi_packages,
        sc_packages,
        sla_policies,
        jira_bug_issuetype,
    )

    collector_obj.store(updated_until_dt=timezone.now())
    logger.info("PS Constants sync was successful.")
    return f"The run of {collector_obj.name} finished."
