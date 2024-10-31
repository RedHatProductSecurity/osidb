from datetime import datetime, timezone

import pytest
from freezegun import freeze_time

from osidb.models import PsModule


class TestPsModule:
    @freeze_time(datetime(2020, 10, 20, tzinfo=timezone.utc))
    @pytest.mark.parametrize(
        "supported_from,supported_until,is_prodsec_supported",
        [
            (
                datetime(2020, 10, 10, tzinfo=timezone.utc),
                datetime(2020, 10, 30, tzinfo=timezone.utc),
                True,
            ),
            (
                datetime(2020, 10, 10, tzinfo=timezone.utc),
                datetime(2020, 10, 10, tzinfo=timezone.utc),
                False,
            ),
            (
                datetime(2020, 10, 30, tzinfo=timezone.utc),
                datetime(2020, 10, 30, tzinfo=timezone.utc),
                True,  # support start in the future should not restrict ProdSec support
            ),
            (
                None,
                datetime(2020, 10, 30, tzinfo=timezone.utc),
                True,
            ),
            (
                datetime(2020, 10, 10, tzinfo=timezone.utc),
                None,
                True,
            ),
        ],
    )
    def test_is_prodsec_supported(
        self, supported_from, supported_until, is_prodsec_supported
    ):
        assert (
            PsModule(
                supported_from_dt=supported_from,
                supported_until_dt=supported_until,
            ).is_prodsec_supported
            == is_prodsec_supported
        )
