import pytest

from osidb.models import PsProduct

pytestmark = pytest.mark.unit


class TestPsProduct:
    @pytest.mark.parametrize(
        "label,is_middleware",
        [
            ("middleware", True),
            ("services", False),
            ("platforms", False),
            ("", False),
            (None, False),
        ],
    )
    def test_is_middleware(self, label, is_middleware):
        # is_middleware is derived purely from the label attribute
        assert PsProduct(label=label).is_middleware == is_middleware

    @pytest.mark.parametrize(
        "label,is_service",
        [
            ("services", True),
            ("middleware", False),
            ("platforms", False),
            ("", False),
            (None, False),
        ],
    )
    def test_is_service(self, label, is_service):
        # is_service is derived purely from the label attribute
        assert PsProduct(label=label).is_service == is_service

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
