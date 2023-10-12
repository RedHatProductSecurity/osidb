from datetime import datetime

import pytest
from django.core.exceptions import ValidationError
from django.test.utils import isolate_apps
from rest_framework.viewsets import ModelViewSet

from osidb.api_views import get_valid_http_methods
from osidb.core import set_user_acls
from osidb.exceptions import OSIDBException
from osidb.models import Flaw, FlawMeta, FlawReference, PsContact
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    FlawMetaFactory,
    FlawReferenceFactory,
)
from osidb.tests.models import (
    TestAlertModel,
    TestAlertModelBasic,
    TestComparableTextChoices_1,
    TestComparableTextChoices_2,
)

pytestmark = pytest.mark.unit


class TestCore(object):
    def test_test(self):
        """test the tests ..."""
        assert 1 == 1

    def test_flaw_factory(self):
        """test that we can generate a flaw using factory"""
        flaw1 = FlawFactory.build(
            major_incident_state=Flaw.FlawMajorIncident.APPROVED,
            requires_summary=Flaw.FlawRequiresSummary.APPROVED,
        )
        flaw1.save(raise_validation_error=False)
        FlawMetaFactory(
            flaw=flaw1,
            type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
            meta_attr={"status": "+"},
        )
        FlawReferenceFactory(
            flaw=flaw1,
            type=FlawReference.FlawReferenceType.ARTICLE,
            url="https://access.redhat.com/link123",
        )
        AffectFactory(flaw=flaw1)
        assert flaw1.save() is None
        assert "test" in flaw1.meta_attr

    def test_flaw_factory_dt(self):
        """
        test that the tracking timestamps are being set by the factories
        """
        flaw = FlawFactory(
            created_dt="2022-03-13T12:54:13Z",
            updated_dt="2023-03-13T12:54:13Z",
        )
        assert flaw.created_dt == datetime(
            2022, 3, 13, 12, 54, 13, tzinfo=flaw.created_dt.tzinfo
        )
        assert flaw.updated_dt == datetime(
            2023, 3, 13, 12, 54, 13, tzinfo=flaw.updated_dt.tzinfo
        )

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
    def test_alert_deletion(self):
        """
        Tests that when calling validate() method, all existing alerts
        are deleted, and new ones are created and stored.
        """
        m = TestAlertModel()
        m.alert("original_alert", "This is an alert from the previous run.")
        assert "original_alert" in m._alerts

        # validate() is called inside save()
        m.save()
        assert "original_alert" not in m._alerts
        assert m._alerts == {
            "new_alert": {
                "type": "warning",
                "description": "This is a new alert.",
                "resolution_steps": "",
            }
        }

    @isolate_apps("tests")
    def test_alert_incorrect_type(self):
        m = TestAlertModel()
        with pytest.raises(ValueError) as e:
            m.alert("my_error", "This is a weird error", _type="weird")
        assert "Alert type 'weird' is not valid" in str(e)

    def test_ps_contact_empty(self):
        """
        test that even an empty PS contact can be properly stored to DB as there
        are no restrictions on the attributes being present - reproducer for OSIDB-1445
        """
        try:
            PsContact(username="unique_name").save()
        except ValidationError:
            pytest.fail("PS contact creation should not fail here")


class TestComparableTextChoices:
    def test_incomparable(self):
        instance1 = TestComparableTextChoices_1(
            TestComparableTextChoices_1.get_choices()[0]
        )
        instance2 = TestComparableTextChoices_2(
            TestComparableTextChoices_2.get_choices()[0]
        )

        # even without equality being defined
        # Python can decide this on identiy
        assert not instance1 == instance2
        assert instance1 != instance2

        with pytest.raises(TypeError) as e:
            assert instance1 < instance2
        assert "'<' not supported" in str(e)

        with pytest.raises(TypeError) as e:
            assert instance1 <= instance2
        assert "'<=' not supported" in str(e)

        with pytest.raises(TypeError) as e:
            assert instance1 > instance2
        assert "'>' not supported" in str(e)

        with pytest.raises(TypeError) as e:
            assert instance1 >= instance2
        assert "'>=' not supported" in str(e)
