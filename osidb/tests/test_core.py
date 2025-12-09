from datetime import datetime

import pytest
from django.core.exceptions import ValidationError
from django.test.utils import isolate_apps
from packageurl import PackageURL
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
    PURLTestModel,
)

pytestmark = pytest.mark.unit


class TestCore(object):
    def test_test(self):
        """test the tests ..."""
        assert 1 == 1

    def test_flaw_factory(self):
        """test that we can generate a flaw using factory"""
        flaw1 = FlawFactory.build(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
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
        assert m.valid_alerts.count() == 1
        alert = m.valid_alerts.first()
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


class TestPURLField:
    """Test PURLField conversion, validation, and normalization"""

    @isolate_apps("tests")
    def test_purl_string_to_packageurl_conversion(self, db):
        """Test that accessing purl field returns PackageURL object"""
        model = PURLTestModel(purl="pkg:pypi/django@4.2.0")
        model.save()

        # Refresh from database to ensure we're testing from_db_value
        model.refresh_from_db()

        # Accessing the field should return a PackageURL object
        assert isinstance(model.purl, PackageURL)
        assert model.purl.type == "pypi"
        assert model.purl.name == "django"
        assert model.purl.version == "4.2.0"

    @isolate_apps("tests")
    def test_purl_packageurl_to_string_conversion(self, db):
        """Test that saving PackageURL object stores normalized string"""
        purl_obj = PackageURL(type="pypi", name="django", version="4.2.0")
        model = PURLTestModel(purl=purl_obj)
        model.save()

        # Check that the stored value is a normalized string by querying directly
        from django.db import connection

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT purl FROM tests_purltestmodel WHERE uuid = %s",
                [str(model.uuid)],
            )
            row = cursor.fetchone()
            stored_value = row[0] if row else None

        # The stored value should be a normalized string
        assert isinstance(stored_value, str)
        assert stored_value == "pkg:pypi/django@4.2.0"

    @isolate_apps("tests")
    def test_purl_validation_invalid_string(self, db):
        """Test that invalid PURL strings raise ValidationError"""
        model = PURLTestModel(purl="not-a-valid-purl")

        with pytest.raises(ValidationError) as exc_info:
            model.full_clean()

        assert "Invalid PURL" in str(exc_info.value)

    @isolate_apps("tests")
    def test_purl_normalization(self, db):
        """Test that PURLs are normalized when stored (e.g., qualifier order)"""
        # Create a PURL with qualifiers in a specific order
        # The normalization should ensure consistent ordering
        purl_string = "pkg:pypi/django@4.2.0?extra=value&another=test"
        model = PURLTestModel(purl=purl_string)
        model.save()

        # Refresh and check that the stored value is normalized
        model.refresh_from_db()

        # The stored string should be normalized
        # We can verify this by checking that to_string() matches
        stored_purl = model.purl
        assert isinstance(stored_purl, PackageURL)
        # The normalized string should match what PackageURL.to_string() produces
        normalized_string = stored_purl.to_string()
        model2 = PURLTestModel(purl=normalized_string)
        model2.save()
        model2.refresh_from_db()
        assert model2.purl.to_string() == normalized_string

    @isolate_apps("tests")
    def test_purl_empty_value(self, db):
        """Test that empty/None PURL values are handled correctly"""
        # Test with None
        model1 = PURLTestModel(purl=None)
        model1.save()
        model1.refresh_from_db()
        assert model1.purl is None

        # Test with empty string
        model2 = PURLTestModel(purl="")
        model2.save()
        model2.refresh_from_db()
        assert model2.purl is None

    @isolate_apps("tests")
    def test_purl_round_trip(self, db):
        """Test that saving and retrieving a PURL maintains consistency"""
        original_purl = "pkg:pypi/django@4.2.0"
        model = PURLTestModel(purl=original_purl)
        model.save()

        # Retrieve from database
        retrieved_model = PURLTestModel.objects.get(pk=model.pk)

        # The retrieved PURL should be a PackageURL object
        assert isinstance(retrieved_model.purl, PackageURL)
        # Converting back to string should match the normalized original
        assert (
            retrieved_model.purl.to_string()
            == PackageURL.from_string(original_purl).to_string()
        )

    @isolate_apps("tests")
    def test_purl_direct_packageurl_assignment(self, db):
        """Test that directly assigning a PackageURL object works"""
        purl_obj = PackageURL(type="npm", name="lodash", version="4.17.21")
        model = PURLTestModel(purl=purl_obj)
        model.save()

        model.refresh_from_db()
        assert isinstance(model.purl, PackageURL)
        assert model.purl.type == "npm"
        assert model.purl.name == "lodash"
        assert model.purl.version == "4.17.21"

    @isolate_apps("tests")
    def test_purl_complex_qualifiers(self, db):
        """Test PURL with complex qualifiers and subpath"""
        purl_string = (
            "pkg:oci/nginx@sha256:abc123?"
            "repository_url=registry.redhat.io/ubi9&tag=latest"
        )
        model = PURLTestModel(purl=purl_string)
        model.save()

        model.refresh_from_db()
        assert isinstance(model.purl, PackageURL)
        assert model.purl.type == "oci"
        assert model.purl.name == "nginx"
        assert model.purl.qualifiers is not None
        assert "repository_url" in model.purl.qualifiers
        assert model.purl.qualifiers.get("repository_url") == "registry.redhat.io/ubi9"  # type: ignore
