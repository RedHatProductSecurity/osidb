import pytest
from freezegun import freeze_time

from osidb.models import Affect, Flaw, FlawCVSS
from osidb.tests.factories import AffectFactory, FlawCVSSFactory, FlawFactory

from .test_flaw import tzdatetime

pytestmark = pytest.mark.unit


class TestCustomQuerySet:
    @pytest.mark.parametrize(
        "model, factory, fields",
        [
            (
                Affect,
                AffectFactory,
                {"affectedness": Affect.AffectAffectedness.NOTAFFECTED},
            ),
            (Flaw, FlawFactory, {"title": "new title"}),
            (FlawCVSS, FlawCVSSFactory, {"version": FlawCVSS.CVSSVersion.VERSION3}),
        ],
    )
    def test_inject_updated_dt(self, model, factory, fields):
        """Test that updated_dt field is injected into the queryset if not present"""
        model_instance = factory()

        with freeze_time(tzdatetime(2024, 11, 8, 12, 0, 0)):
            update_count = model.objects.filter(uuid=model_instance.uuid).update(
                **fields
            )

        model_instance.refresh_from_db()

        assert update_count == 1
        assert (
            getattr(model_instance, list(fields.keys())[0]) == list(fields.values())[0]
        )
        assert model_instance.updated_dt == tzdatetime(2024, 11, 8, 12, 0, 0)

    @pytest.mark.parametrize(
        "model, factory, fields",
        [
            (
                Affect,
                AffectFactory,
                {"affectedness": Affect.AffectAffectedness.NOTAFFECTED},
            ),
            (Flaw, FlawFactory, {"title": "new title"}),
            (FlawCVSS, FlawCVSSFactory, {"version": FlawCVSS.CVSSVersion.VERSION3}),
        ],
    )
    def test_no_inject_updated_dt(self, model, factory, fields):
        """Test that updated_dt field is not injected into the queryset if present"""
        model_instance = factory()

        with freeze_time(tzdatetime(2024, 11, 8, 12, 0, 0)):
            update_count = model.objects.filter(uuid=model_instance.uuid).update(
                **fields, updated_dt=tzdatetime(2024, 11, 9, 13, 0, 0)
            )

        model_instance.refresh_from_db()

        assert update_count == 1
        assert (
            getattr(model_instance, list(fields.keys())[0]) == list(fields.values())[0]
        )
        assert model_instance.updated_dt == tzdatetime(2024, 11, 9, 13, 0, 0)
