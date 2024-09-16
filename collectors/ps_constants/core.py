import logging

import requests
import yaml
from django.conf import settings
from django.db import transaction
from requests_gssapi import HTTPSPNEGOAuth

from apps.sla.models import SLA, SLAPolicy
from apps.trackers.models import JiraBugIssuetype
from osidb.dmodels import SpecialConsiderationPackage, UbiPackage

logger = logging.getLogger(__name__)


def fetch_ps_constants(url, multi=False):
    """
    Fetch PS constants from given url.

    :param multi: Whether the YAML data contains multiple files.
    """
    response = requests.get(
        url=url,
        params={"job": "build"},
        auth=HTTPSPNEGOAuth(),
        timeout=settings.DEFAULT_REQUEST_TIMEOUT,
    )
    response.raise_for_status()

    try:
        if not multi:
            return yaml.safe_load(response.text)
        return yaml.safe_load_all(response.text)
    except yaml.YAMLError as e:
        print("Error parsing YAML:", e)


@transaction.atomic
def sync_ubi_packages(ubi_packages):
    """
    Sync a dict of major rhel versions
    with its ubi components
    """
    UbiPackage.objects.all().delete()
    for major, packages in ubi_packages.items():
        for package_name in packages:
            package = UbiPackage(name=package_name, major_stream_version=major)
            package.save()


@transaction.atomic
def sync_special_consideration_packages(sc_packages):
    """
    Sync a list of special consideration components
    """
    SpecialConsiderationPackage.objects.all().delete()
    for name in sc_packages:
        package = SpecialConsiderationPackage(name=name)
        package.save()


@transaction.atomic
def sync_sla_policies(sla_policies):
    """
    Sync SLA policy data
    """
    SLA.objects.all().delete()
    SLAPolicy.objects.all().delete()
    for order, policy_desc in enumerate(sla_policies):
        # In SLA policies order is important so it is passed down to the model
        policy = SLAPolicy.create_from_description(policy_desc, order)
        policy.save()


@transaction.atomic
def sync_jira_bug_issuetype(source_dict):
    """
    sync Jira Bug issuetype data (controls which projects should have Trackers
    created with Bug issuetype instead of Vulnerability issuetype)
    """
    JiraBugIssuetype.objects.all().delete()
    for project in list(source_dict.values())[0]:
        JiraBugIssuetype.objects.get_or_create(project=project)
