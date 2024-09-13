from typing import Tuple

import requests
from django.conf import settings
from django.db import transaction
from django.utils.timezone import datetime, make_aware
from requests_gssapi import HTTPSPNEGOAuth

from osidb.dmodels import PsModule, PsProduct
from osidb.helpers import ensure_list, get_model_fields
from osidb.models import PsContact, PsUpdateStream

from .constants import (
    PRODUCT_DEFINITIONS_REPO_BRANCH,
    PRODUCT_DEFINITIONS_REPO_URL,
    PROPERTIES_MAP,
    PS_UPDATE_STREAM_RELATIONSHIP_TYPE,
)

# GitLab URL to specific branch
PRODUCT_DEFINITIONS_URL = "/".join(
    (
        PRODUCT_DEFINITIONS_REPO_URL,
        "-",
        "jobs",
        "artifacts",
        PRODUCT_DEFINITIONS_REPO_BRANCH,
        "raw",
        "products.json",
    )
)


def fetch_product_definitions(url=PRODUCT_DEFINITIONS_URL):
    """Fetch Product Definitions from given url"""
    response = requests.get(
        url=url,
        params={"job": "build"},
        auth=HTTPSPNEGOAuth(),
        timeout=settings.DEFAULT_REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def sanitize_product_definitions(data: dict) -> Tuple[dict, dict, dict, dict]:
    """
    adjust product definitions data obtained from gitlab

    returns tuple with sanitized product definitions in this order:
    ps_products, ps_modules, ps_update_streams, contacts
    """

    # remap nested properties to normal properties
    for data_type, properties in PROPERTIES_MAP.items():
        for item in data[data_type].values():
            for property_name, _property in properties.items():
                for nested_property_name, new_property_name in _property.items():
                    new_property_value = item.get(property_name, {}).get(
                        nested_property_name
                    )
                    if new_property_value is not None:
                        item[new_property_name] = new_property_value

    return (
        data["ps_products"],
        data["ps_modules"],
        data["ps_update_streams"],
        # TODO: Not sure about the usage since it was not very clear
        # from the SFM2 codebase, we can eventually drop this one
        data["contacts"],
    )


@transaction.atomic
def sync_ps_contacts(data: dict):
    """
    clean and re-create PS contacts from given data
    """
    PsContact.objects.all().delete()

    ps_contact_fields = get_model_fields(PsContact)
    for contact_username, contact_data in data.items():
        filtered_contact_data = {
            key: value
            for key, value in contact_data.items()
            if key in ps_contact_fields
        }

        PsContact.objects.create(username=contact_username, **filtered_contact_data)


@transaction.atomic
def sync_ps_update_streams(data: dict):
    """
    clean and re-create PS update streams from given data
    """
    PsUpdateStream.objects.all().delete()

    ps_update_stream_fields = get_model_fields(PsUpdateStream)
    for stream_name, stream_data in data.items():
        filtered_stream_data = {
            key: value
            for key, value in stream_data.items()
            if key in ps_update_stream_fields
        }

        PsUpdateStream.objects.create(name=stream_name, **filtered_stream_data)


@transaction.atomic
def sync_ps_products_modules(ps_products_data: dict, ps_modules_data: dict):
    """
    clean and re-create PS products and PS module from given data
    """
    PsModule.objects.all().delete()
    PsProduct.objects.all().delete()

    ps_product_fields = get_model_fields(PsProduct)
    ps_module_fields = get_model_fields(PsModule)
    for product_short_name, product_data in ps_products_data.items():
        filtered_product_data = {
            key: value
            for key, value in product_data.items()
            if key in ps_product_fields
        }
        related_ps_modules = filtered_product_data.pop("ps_modules")

        ps_product = PsProduct.objects.create(
            short_name=product_short_name, **filtered_product_data
        )

        # Sync PS Product related PS Modules
        for module_name in related_ps_modules:
            module_data = ps_modules_data[module_name]
            filtered_module_data = {}
            for fname in ps_module_fields:
                if val := module_data.get(fname, False):
                    filtered_module_data[fname] = val

            # get names of the related PS Update Streams as they will be
            # synced separately after PS Module creation
            related_ps_update_streams = {
                stream_type: filtered_module_data.pop(stream_type)
                for stream_type in PS_UPDATE_STREAM_RELATIONSHIP_TYPE
                if stream_type in filtered_module_data
            }

            # TODO note that the following is probably incorrect somehow as
            # we're attempting to set multiple related objects with string
            # values but Django doesn't seem to care?

            # convert string date to an object aware of a given time zone
            for supported_dt in ["supported_from_dt", "supported_until_dt"]:
                if date := filtered_module_data.get(supported_dt):
                    filtered_module_data[supported_dt] = make_aware(
                        datetime.strptime(date, "%Y-%m-%d")
                    )

            ps_module = PsModule.objects.create(
                name=module_name, ps_product=ps_product, **filtered_module_data
            )

            # Create relations with related PS Update Streams
            for stream_type, stream_names in related_ps_update_streams.items():
                field = getattr(ps_module, stream_type)
                field.set(
                    # unacked PS update stream is string unlinke the others
                    # so we have to turn it into a list while not touch the others
                    PsUpdateStream.objects.filter(name__in=ensure_list(stream_names))
                )
                # unacked PS update stream may or may not be present in ps_updates_streams array
                # therefore we need to explicitly ensure that it is linked to PS module
                if stream_type == "unacked_ps_update_stream":
                    unacked_ps_update_stream = PsUpdateStream.objects.filter(
                        name=stream_names
                    ).first()
                    if unacked_ps_update_stream:
                        ps_module.ps_update_streams.add(unacked_ps_update_stream)
