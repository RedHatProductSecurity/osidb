"""
tests related to the test factories
"""

from datetime import datetime, timezone

import pytest

from osidb.models import Affect, Flaw, FlawCVSS, Impact, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawCVSSFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
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
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            created_dt="2000-10-10T00:00:00Z",
            updated_dt="2000-10-10T00:00:00Z",
        )
        assert tracker.created_dt == datetime(2000, 10, 10, tzinfo=timezone.utc)
        assert tracker.updated_dt == datetime(2000, 10, 10, tzinfo=timezone.utc)


class TestFlawCVSSFactory:
    @pytest.mark.parametrize(
        "vector,impact",
        [
            # 7.2
            ("CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", Impact.MODERATE),
            # 0.0
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", Impact.NOVALUE),
        ],
    )
    def test_rh_cvss3_and_impact(self, vector, impact):
        """
        Test that flaw and its impact are correctly created from RH CVSSv3 score
        """
        FlawCVSSFactory(
            version=FlawCVSS.CVSSVersion.VERSION3,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            vector=vector,
        )

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.impact == impact
