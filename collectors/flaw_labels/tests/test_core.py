import pytest

from collectors.flaw_labels.core import fetch_flaw_labels, sync_flaw_labels
from osidb.helpers import get_model_fields
from osidb.models import FlawLabel

pytestmark = pytest.mark.unit


class TestFlawLabelsCollection:
    def check_model_fields(self, model, data):
        fields = get_model_fields(model)
        for label, filters in data.items():
            instance = FlawLabel.objects.get(name=label)
            for field, value in filters.items():
                if field in fields:
                    assert getattr(instance, field) == value

    @pytest.mark.vcr
    def test_fetch_flaw_labels(self, flaw_labels_url):
        """Check collector is capable of pull data from gitlab"""
        flaw_labels = fetch_flaw_labels(flaw_labels_url)

        assert len(flaw_labels) == 3
        (context_based, product_family, bu_labels) = flaw_labels

        assert len(context_based) == 9
        assert len(product_family) == 13
        assert len(product_family["special-handling"]["ps_components"]) == 6
        assert len(bu_labels) == 4

    @pytest.mark.default_cassette(
        "TestFlawLabelsCollection.test_fetch_flaw_labels.yaml"
    )
    @pytest.mark.vcr
    def test_sync_flaw_labels(self, flaw_labels_url):
        (context_based, product_family, bu_labels) = fetch_flaw_labels(flaw_labels_url)

        sync_flaw_labels(context_based, product_family, bu_labels)

        assert FlawLabel.objects.filter(
            type=FlawLabel.FlawLabelType.CONTEXT_BASED
        ).count() == len(context_based)
        assert FlawLabel.objects.filter(
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY
        ).count() == len(product_family)
        assert FlawLabel.objects.filter(type=FlawLabel.FlawLabelType.BU).count() == len(
            bu_labels
        )

        self.check_model_fields(FlawLabel, context_based)
        self.check_model_fields(FlawLabel, product_family)
        self.check_model_fields(FlawLabel, bu_labels)
