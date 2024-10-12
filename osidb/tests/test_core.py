from datetime import datetime

import pytest
from django.core.exceptions import ValidationError
from django.test.utils import isolate_apps
from rest_framework.viewsets import ModelViewSet

from osidb.api_views import get_valid_http_methods
from osidb.core import set_user_acls
from osidb.exceptions import OSIDBException
from osidb.mixins import Alert
from osidb.models import Flaw, FlawReference, PsContact
from osidb.tests.factories import AffectFactory, FlawFactory, FlawReferenceFactory
from osidb.tests.models import (
    AlertableModel,
    AlertableModelBasic,
    ComparableTextChoices_1,
    ComparableTextChoices_2,
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
            requires_cve_description=Flaw.FlawRequiresCVEDescription.APPROVED,
        )
        flaw1.save(raise_validation_error=False)
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
        m = AlertableModelBasic()
        m.save()

        assert not m.alerts.exists()

    @isolate_apps("tests")
    def test_alert_deletion(self):
        """
        Tests that when calling validate() method, all existing alerts
        are deleted, and new ones are created and stored.
        """
        m = AlertableModel()
        m.alert("original_alert", "This is an alert from the previous run.")
        assert m.alerts.count() == 1
        assert m.alerts.first().name == "original_alert"
        assert m.alerts.first().description == "This is an alert from the previous run."

        # validate() is called inside save()
        m.save()
        assert m.alerts.count() == 1
        alert = m.alerts.first()
        assert alert.name == "new_alert"
        assert alert.alert_type == Alert.AlertType.WARNING
        assert alert.description == "This is a new alert."
        assert alert.resolution_steps == ""

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
        instance1 = ComparableTextChoices_1(ComparableTextChoices_1.get_choices()[0])
        instance2 = ComparableTextChoices_2(ComparableTextChoices_2.get_choices()[0])

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
