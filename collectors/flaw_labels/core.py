import logging

import requests
import yaml
from django.conf import settings
from django.db import transaction
from requests_gssapi import HTTPSPNEGOAuth

from osidb.helpers import ensure_list, get_model_fields
from osidb.models import FlawLabel

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
        return (labels["context_based_labels"], labels["product_family_labels"])
    except yaml.YAMLError as e:
        logger.error("Error parsing YAML", exc_info=e)


def sync_flaw_labels(context_based: dict, product_family: dict):
    """
    clean and re-create Flaw labels from given data
    """

    flaw_labels = []
    flaw_label_fields = get_model_fields(FlawLabel)

    for flaw_label, filters in context_based.items():
        filtered_data = {
            key: ensure_list(value)
            for key, value in filters.items()
            if key in flaw_label_fields
        }
        flaw_labels.append(
            FlawLabel(
                name=flaw_label,
                type=FlawLabel.FlawLabelType.CONTEXT_BASED,
                **filtered_data
            )
        )

    for flaw_label, filters in product_family.items():
        filtered_data = {
            key: ensure_list(value)
            for key, value in filters.items()
            if key in flaw_label_fields
        }
        flaw_labels.append(
            FlawLabel(
                name=flaw_label,
                type=FlawLabel.FlawLabelType.PRODUCT_FAMILY,
                **filtered_data
            )
        )

    with transaction.atomic():
        FlawLabel.objects.all().delete()
        FlawLabel.objects.bulk_create(flaw_labels)
