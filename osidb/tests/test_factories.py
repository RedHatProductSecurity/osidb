"""
tests related to the test factories
"""
import pytest
from django.utils import timezone

from osidb.models import Affect, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestTrackerFactory:
    """
    TrackerFactory specific tests
    """

    def test_assigning_timestamps(self):
        """
        test that the timestamp values are actually being set
        """
        flaw = FlawFactory()
        ps_module = PsModuleFactory()
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=flaw.embargoed,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            created_dt="2000-10-10T00:00:00Z",
            updated_dt="2000-10-10T00:00:00Z",
        )
        assert tracker.created_dt == timezone.datetime(
            2000, 10, 10, tzinfo=timezone.utc
        )
        assert tracker.updated_dt == timezone.datetime(
            2000, 10, 10, tzinfo=timezone.utc
        )
