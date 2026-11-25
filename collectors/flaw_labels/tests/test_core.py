import pytest

from collectors.flaw_labels.core import fetch_flaw_labels, sync_flaw_labels
from osidb.helpers import get_model_fields
from osidb.models import (
    CollaboratorLabelDefinition,
    ProductFamilyLabelDefinition,
)

pytestmark = pytest.mark.unit


class TestFlawLabelsCollection:
    def check_model_fields(self, model, data):
        fields = get_model_fields(model)
        for label, filters in data.items():
            instance = model.objects.get(name=label)
            for field, value in filters.items():
                if field in fields:
                    assert getattr(instance, field) == value

    @pytest.mark.vcr
    def test_fetch_flaw_labels(self, flaw_labels_url):
        """Check collector is capable of pull data from gitlab"""
        flaw_labels = fetch_flaw_labels(flaw_labels_url)

        assert len(flaw_labels) == 2
        (context_based, product_family) = flaw_labels

        assert len(context_based) == 9
        assert len(product_family) == 13
        assert len(product_family["special-handling"]["ps_components"]) == 6

    @pytest.mark.default_cassette(
        "TestFlawLabelsCollection.test_fetch_flaw_labels.yaml"
    )
    @pytest.mark.vcr
    def test_sync_flaw_labels(self, flaw_labels_url):
        (context_based, product_family) = fetch_flaw_labels(flaw_labels_url)

        sync_flaw_labels(context_based, product_family)

        assert CollaboratorLabelDefinition.objects.count() == len(context_based)
        assert ProductFamilyLabelDefinition.objects.count() == len(product_family)

        self.check_model_fields(ProductFamilyLabelDefinition, product_family)
