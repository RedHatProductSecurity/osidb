import pytest
from django.test.utils import isolate_apps
from rest_framework.viewsets import ModelViewSet

from osidb.core import set_user_acls
from osidb.exceptions import OSIDBException
from osidb.helpers import get_valid_http_methods
from osidb.models import FlawMeta
from osidb.tests.factories import AffectFactory, FlawFactory, FlawMetaFactory
from osidb.tests.models import TestAlertModel, TestAlertModelBasic

pytestmark = pytest.mark.unit


class TestCore(object):
    def test_test(self):
        """test the tests ..."""
        assert 1 == 1

    def test_flaw_factory(self):
        """test that we can generate a flaw using factory"""
        flaw1 = FlawFactory.build(is_major_incident=True)
        flaw1.save(raise_validation_error=False)
        FlawMetaFactory(
            flaw=flaw1,
            type=FlawMeta.FlawMetaType.REQUIRES_DOC_TEXT,
            meta_attr={"status": "+"},
        )
        AffectFactory(flaw=flaw1)
        assert flaw1.save() is None
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


class TestModelDefinitions:
    @isolate_apps("tests")
    def test_creation_empty_alerts(self):
        m = TestAlertModelBasic()
        m.save()

        assert m._alerts == {}

    @isolate_apps("tests")
    def test_alert_inheritance(self):
        m = TestAlertModel()
        m.save()

        assert m._alerts == {
            "my_alert": {
                "type": "warning",
                "description": "This alert be danger",
                "resolution_steps": "",
            }
        }

    @isolate_apps("tests")
    def test_alert_create(self):
        m = TestAlertModel()
        m.alert("my_error", "This is an error", _type="error", resolution_steps="pray")
        m.save()

        assert len(m._alerts) == 2
        assert m._alerts["my_error"] == {
            "type": "error",
            "description": "This is an error",
            "resolution_steps": "pray",
        }

    @isolate_apps("tests")
    def test_alert_incorrect_type(self):
        m = TestAlertModel()
        with pytest.raises(ValueError) as e:
            m.alert("my_error", "This is a weird error", _type="weird")
        assert "Alert type 'weird' is not valid" in str(e)
