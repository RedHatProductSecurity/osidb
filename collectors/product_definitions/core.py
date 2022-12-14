from typing import Tuple

import requests
from requests_gssapi import HTTPSPNEGOAuth

from osidb.helpers import get_model_fields
from osidb.models import PsContact, PsModule, PsProduct, PsUpdateStream

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


def sync_ps_contacts(data: dict):
    """Create or update PS Contacts based from given data"""
    ps_contact_fields = get_model_fields(PsContact)
    for contact_username, contact_data in data.items():
        filtered_contact_data = {
            key: value
            for key, value in contact_data.items()
            if key in ps_contact_fields
        }

        PsContact.objects.update_or_create(
            username=contact_username, defaults=filtered_contact_data
        )


def sync_ps_update_streams(data: dict):
    """Create or update PS Update Streams based from given data"""
    ps_update_stream_fields = get_model_fields(PsUpdateStream)
    for stream_name, stream_data in data.items():
        filtered_stream_data = {
            key: value
            for key, value in stream_data.items()
            if key in ps_update_stream_fields
        }

        PsUpdateStream.objects.update_or_create(
            name=stream_name, defaults=filtered_stream_data
        )


def ensure_list(item):
    """
    helper to ensure that the item is list
    """
    return item if isinstance(item, list) else [item]


def sync_ps_products_modules(ps_products_data: dict, ps_modules_data: dict):
    """
    Create or update PS Products based from given data and for each
    PS Product create PS Modules
    """
    ps_product_fields = get_model_fields(PsProduct)
    ps_module_fields = get_model_fields(PsModule)
    for product_short_name, product_data in ps_products_data.items():
        filtered_product_data = {
            key: value
            for key, value in product_data.items()
            if key in ps_product_fields
        }
        related_ps_modules = filtered_product_data.pop("ps_modules")

        ps_product, _ = PsProduct.objects.update_or_create(
            short_name=product_short_name, defaults=filtered_product_data
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
            ps_module, _ = PsModule.objects.update_or_create(
                name=module_name,
                defaults={"ps_product": ps_product, **filtered_module_data},
            )

            # Create relations with related PS Update Streams
            for stream_type, stream_names in related_ps_update_streams.items():
                field = getattr(ps_module, stream_type)
                field.set(
                    # unacked PS update stream is string unlinke the others
                    # so we have to turn it into a list while not touch the others
                    PsUpdateStream.objects.filter(name__in=ensure_list(stream_names))
                )
