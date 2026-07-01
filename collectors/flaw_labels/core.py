import logging

import requests
import yaml
from django.conf import settings
from django.db import transaction
from requests_gssapi import HTTPSPNEGOAuth

from osidb.helpers import ensure_list, get_model_fields
from osidb.models import (
    BULabelDefinition,
    CollaboratorLabelDefinition,
    ProductFamilyLabelDefinition,
)

logger = logging.getLogger(__name__)


def fetch_flaw_labels(url):
    """
    Fetch Flaw Labels from given url.
    """
    response = requests.get(
        url=url,
        auth=HTTPSPNEGOAuth(),
        timeout=settings.DEFAULT_REQUEST_TIMEOUT,
    )
    response.raise_for_status()

    try:
        labels = yaml.safe_load(response.text)
        return (
            labels["context_based_labels"],
            labels["product_family_labels"],
            labels["bu_labels"],
        )
    except yaml.YAMLError as e:
        logger.error("Error parsing YAML", exc_info=e)


def sync_flaw_labels(context_based: dict, product_family: dict, bu_labels: dict):
    """
    clean and re-create Flaw labels from given data
    """

    collaborator_defs = []
    product_family_defs = []
    bu_defs = []
    pf_def_fields = get_model_fields(ProductFamilyLabelDefinition)

    for name in context_based:
        collaborator_defs.append(CollaboratorLabelDefinition(name=name))

    for name, filters in product_family.items():
        filtered_data = {
            key: ensure_list(value)
            for key, value in filters.items()
            if key in pf_def_fields
        }
        product_family_defs.append(
            ProductFamilyLabelDefinition(name=name, **filtered_data)
        )

    for name in bu_labels:
        bu_defs.append(BULabelDefinition(name=name))

    with transaction.atomic():
        CollaboratorLabelDefinition.objects.all().delete()
        CollaboratorLabelDefinition.objects.bulk_create(collaborator_defs)

        ProductFamilyLabelDefinition.objects.all().delete()
        ProductFamilyLabelDefinition.objects.bulk_create(product_family_defs)

        BULabelDefinition.objects.all().delete()
        BULabelDefinition.objects.bulk_create(bu_defs)
