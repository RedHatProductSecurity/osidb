import pytest

from osidb.models import PsProduct

pytestmark = pytest.mark.unit


class TestPsProduct:
    @pytest.mark.parametrize(
        "team,is_middleware",
        [
            ("middleware", True),
            ("platforms", False),
            ("cloudplatform", False),
            ("", False),
            (None, False),
        ],
    )
    def test_is_middleware(self, team, is_middleware):
        # is_middleware is derived purely from the team attribute
        assert PsProduct(team=team).is_middleware == is_middleware

    @pytest.mark.parametrize(
        "business_unit,is_community",
        [
            ("Community", True),
            ("Core Middleware", False),
            ("", False),
        ],
    )
    def test_is_community(self, business_unit, is_community):
        assert PsProduct(business_unit=business_unit).is_community == is_community
