import pytest
from django.utils import timezone
from freezegun import freeze_time

from osidb.models import PsModule


class TestPsModule:
    @freeze_time(timezone.datetime(2020, 10, 20, tzinfo=timezone.utc))
    @pytest.mark.parametrize(
        "supported_from,supported_until,is_prodsec_supported",
        [
            (
                timezone.datetime(2020, 10, 10, tzinfo=timezone.utc),
                timezone.datetime(2020, 10, 30, tzinfo=timezone.utc),
                True,
            ),
            (
                timezone.datetime(2020, 10, 10, tzinfo=timezone.utc),
                timezone.datetime(2020, 10, 10, tzinfo=timezone.utc),
                False,
            ),
            (
                timezone.datetime(2020, 10, 30, tzinfo=timezone.utc),
                timezone.datetime(2020, 10, 30, tzinfo=timezone.utc),
                True,  # support start in the future should not restrict ProdSec support
            ),
            (
                None,
                timezone.datetime(2020, 10, 30, tzinfo=timezone.utc),
                True,
            ),
            (
                timezone.datetime(2020, 10, 10, tzinfo=timezone.utc),
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
