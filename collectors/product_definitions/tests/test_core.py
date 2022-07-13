from typing import Type

import pytest
from django.db import models

from osidb.helpers import get_model_fields
from osidb.models import PsContact, PsModule, PsProduct, PsUpdateStream

from ..constants import PROPERTIES_MAP
from ..core import (
    fetch_product_definitions,
    sanitize_product_definitions,
    sync_ps_contacts,
    sync_ps_products_modules,
    sync_ps_update_streams,
)

pytestmark = pytest.mark.unit

PRODUCT_DEFINITIONS_CASSETTE = (
    "TestProductDefinitionsCollection.product_definitions.yaml"
)


class TestProductDefinitionsCollection:
    def sample_data(self, raw_data):
        """take only sample of the raw data"""
        to_keep = {
            "ps_modules": [
                "rhint-dv-1",
                "rhint-camel-k-1",
                "rhint-debezium-1",
                "rhint-serv-1",
                "rhint-camel-quarkus-1",
                "rhint-serv-2",
                "rhint-operator-1",
                "rhelsa-7",
                "fuse-7",
                "fuse-6",
                "fis-2",
            ],
            "ps_update_streams": [
                "rhint-dv-1",
                "rhelsa-7.1",
                "rhelsa-7.2",
                "fuse-7",
                "fuse-7.0.0",
                "fuse-7.1.0",
                "fuse-7.2.0",
                "fuse-7.3.0",
                "fuse-7.3.1",
                "fuse-7.4.0",
            ],
            "ps_products": ["rhint", "rhelsa", "fuse"],
        }

        sampled_data = {
            "contacts": {
                key: value for key, value in list(raw_data["contacts"].items())[0:10]
            },
        }

        for data_type, items_to_keep in to_keep.items():
            sampled_data[data_type] = {
                item_to_keep: raw_data[data_type][item_to_keep]
                for item_to_keep in items_to_keep
            }

        return sampled_data

    def check_fields_population(
        self, model: Type[models.Model], unique_field: str, raw_data: dict
    ):
        """Check model fields population compared to raw_data"""
        fields = get_model_fields(model)
        for key, value in raw_data.items():
            instance = model.objects.get(**{unique_field: key})
            for field in raw_data[key]:
                if field in fields:
                    if raw_data[key].get(field):
                        assert getattr(instance, field)

    @pytest.mark.default_cassette(PRODUCT_DEFINITIONS_CASSETTE)
    @pytest.mark.vcr
    def test_sanitize(self):
        raw_data = fetch_product_definitions()
        (
            ps_products,
            ps_modules,
            ps_update_streams,
            ps_contacts,
        ) = sanitize_product_definitions(raw_data)

        def check_sanitized_data(data: dict, data_type: str):
            for property_name, _property in PROPERTIES_MAP.get(data_type, {}).items():
                for nested_property_name, new_property_name in _property.items():
                    for item in data.values():
                        nested_property = item.get(property_name, {}).get(
                            nested_property_name
                        )
                        if nested_property is not None:
                            assert new_property_name in item

        for data, data_type in (
            (ps_products, "ps_products"),
            (ps_modules, "ps_modules"),
            (ps_update_streams, "ps_update_streams"),
            (ps_contacts, "ps_contacts"),
        ):
            check_sanitized_data(data, data_type)

    @pytest.mark.default_cassette(PRODUCT_DEFINITIONS_CASSETTE)
    @pytest.mark.vcr
    def test_ps_contacts_sync(self):
        raw_data = self.sample_data(fetch_product_definitions())
        _, _, _, ps_contacts = sanitize_product_definitions(raw_data)

        sync_ps_contacts(ps_contacts)

        # Check all synced
        assert PsContact.objects.count() == len(ps_contacts)

        # Check fields population
        self.check_fields_population(PsContact, "username", ps_contacts)

    @pytest.mark.default_cassette(PRODUCT_DEFINITIONS_CASSETTE)
    @pytest.mark.vcr
    def test_ps_update_streams_sync(self):
        raw_data = self.sample_data(fetch_product_definitions())
        _, _, ps_update_streams, _ = sanitize_product_definitions(raw_data)

        sync_ps_update_streams(ps_update_streams)

        # Check all synced
        assert PsUpdateStream.objects.count() == len(ps_update_streams)

        # Check fields population
        self.check_fields_population(PsUpdateStream, "name", ps_update_streams)

    @pytest.mark.default_cassette(PRODUCT_DEFINITIONS_CASSETTE)
    @pytest.mark.vcr
    def test_ps_products_modules_sync(self):
        raw_data = self.sample_data(fetch_product_definitions())
        ps_products, ps_modules, _, _ = sanitize_product_definitions(raw_data)

        sync_ps_products_modules(ps_products, ps_modules)

        # Check all synced
        assert PsProduct.objects.count() == len(ps_products)
        assert PsModule.objects.count() == len(ps_modules)

        # Check fields population
        self.check_fields_population(PsProduct, "short_name", ps_products)
        self.check_fields_population(PsModule, "name", ps_modules)

    @pytest.mark.default_cassette(PRODUCT_DEFINITIONS_CASSETTE)
    @pytest.mark.vcr
    def test_additional_ps_update_stream_module_link(self):
        raw_data = self.sample_data(fetch_product_definitions())
        (
            ps_products,
            ps_modules,
            ps_update_streams,
            _,
        ) = sanitize_product_definitions(raw_data)

        # Sync PS Products and Modules without previously
        # syncing Update Streams
        sync_ps_products_modules(ps_products, ps_modules)

        module = PsModule.objects.get(name="fuse-7")
        assert not module.ps_update_streams.all()
        assert not module.active_ps_update_streams.all()
        assert not module.default_ps_update_streams.all()

        # Sync PS Update Streams and resync Products and Modules
        sync_ps_update_streams(ps_update_streams)
        sync_ps_products_modules(ps_products, ps_modules)
        assert module.ps_update_streams.all()
        assert module.active_ps_update_streams.all()
        assert module.default_ps_update_streams.all()
