import logging

import requests
import yaml
from django.conf import settings
from django.db import transaction
from requests_gssapi import HTTPSPNEGOAuth

from osidb.models import (
    CompliancePriority,
    ContractPriority,
    SpecialConsiderationPackage,
    UbiPackage,
)

logger = logging.getLogger(__name__)


def fetch_ps_constants(url):
    """Fetch Product Definitions from given url"""
    response = requests.get(
        url=url,
        params={"job": "build"},
        auth=HTTPSPNEGOAuth(),
        timeout=settings.DEFAULT_REQUEST_TIMEOUT,
    )
    response.raise_for_status()

    try:
        return yaml.safe_load(response.text)
    except yaml.YAMLError as e:
        print("Error parsing YAML:", e)


@transaction.atomic
def sync_compliance_priority(source_dict):
    """
    sync compliance priority data
    """
    CompliancePriority.objects.all().delete()
    for ps_module, json_field in source_dict.items():
        components = json_field.get("components", [])

        streams = json_field.get("streams")
        if streams is None:
            msg = f"Invalid contents (missing streams) in compliance_priority.yml for module {ps_module}."
            logger.error(msg)
            raise RuntimeError(msg)

        CompliancePriority(
            ps_module=ps_module, components=components, streams=streams
        ).save()


@transaction.atomic
def sync_contract_priority(source_dict):
    """
    sync contract priority data
    """
    ContractPriority.objects.all().delete()
    # ps_update_stream is unique across all ps_modules in the hierarchy of product
    # definitions so there's no need to store ps_module, although it is in the
    # source yaml for human readability.
    for ps_update_streams in source_dict.values():
        for ps_update_stream in ps_update_streams:
            ContractPriority(ps_update_stream=ps_update_stream).save()


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
