import pytest
from rest_framework.viewsets import ModelViewSet

from osidb.api_views import get_valid_http_methods
from osidb.core import set_user_acls
from osidb.exceptions import OSIDBException
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


class TestCore(object):
    def test_test(self):
        """test the tests ..."""
        assert 1 == 1

    def test_flaw_factory(self):
        """test that we can generate a flaw using factory"""
        flaw1 = FlawFactory(is_major_incident=True)
        assert "test" in flaw1.meta_attr

    def test_flaw_exceptions(self):
        with pytest.raises(OSIDBException):
            set_user_acls(1)

    def test_valid_http_methods(self, settings):
        base = ModelViewSet.http_method_names.copy()
        # patch is blacklisted by default
        base.remove("patch")
        assert get_valid_http_methods(ModelViewSet) == base

        # reset blacklist and check that there are no changes
        settings.BLACKLISTED_HTTP_METHODS = ()
        assert "patch" in ModelViewSet.http_method_names
        assert get_valid_http_methods(ModelViewSet) == ModelViewSet.http_method_names

        # finally test readonly
        valid = [
            "get",
            "head",
            "options",
        ]
        settings.READONLY_MODE = True
        assert get_valid_http_methods(ModelViewSet) == valid
