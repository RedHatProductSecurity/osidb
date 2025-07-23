import logging

import requests
import yaml
from django.conf import settings
from django.db import transaction
from requests_gssapi import HTTPSPNEGOAuth

from apps.sla.models import SLA, SLAPolicy
from apps.trackers.models import JiraBugIssuetype
from collectors.cveorg.models import Keyword
from osidb.models import SpecialConsiderationPackage

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


@transaction.atomic
def sync_cveorg_keywords(source: dict) -> None:
    """
    Sync CVEorg keywords in the database
    """
    try:
        keywords = [
            (Keyword.Type.ALLOWLIST, source["allowlist"]),
            (Keyword.Type.ALLOWLIST_SPECIAL_CASE, source["allowlist_special_cases"]),
            (Keyword.Type.BLOCKLIST, source["blocklist"]),
            (Keyword.Type.BLOCKLIST_SPECIAL_CASE, source["blocklist_special_cases"]),
            (Keyword.Type.CNA_ASSIGNERORGID_BLOCKLIST, source["cna_assignerOrgId_blocklist"]),
        ]
    except KeyError:
        raise KeyError(
            "The ps-constants repository does not contain the expected CVEorg keyword sections."
        )

    # Delete and recreate keywords
    Keyword.objects.all().delete()
    for keyword_type, data in keywords:
        for entry in data:
            keyword = Keyword(keyword=entry, type=keyword_type)
            keyword.save()
