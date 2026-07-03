import os
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from django.utils import timezone as django_timezone
from freezegun import freeze_time

from osidb.helpers import get_env
from osidb.integrations import IntegrationRepository, IntegrationSettings
from osidb.models import Affect, FlawSource, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)


@pytest.fixture(autouse=True)
def use_debug(settings):
    """Enforce DEBUG=True in all tests because pytest hardcodes it to False

    See: https://github.com/pytest-dev/pytest-django/pull/463

    Once the `--django-debug-mode` option is added to pytest, we can get rid of this fixture and
    use the CLI setting via pytest.ini:
    https://docs.pytest.org/en/latest/customize.html#adding-default-options
    """
    settings.DEBUG = True


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture
def root_url():
    return "http://osidb-service:8000"


@pytest.fixture
def command_curl():
    """define path to curl"""
    test_curl_path = get_env("TEST_CURL_PATH")
    if test_curl_path is not None:
        return test_curl_path
    return "/usr/bin/curl"


@pytest.fixture
def datetime_with_tz():
    return datetime.now(timezone.utc)


@pytest.fixture
def good_cve_id():
    return "CVE-2000-101010"


@pytest.fixture
def good_cve_id2():
    return "CVE-2021-999999"


@pytest.fixture
def test_user_dict():
    return {
        "username": "foo",
        "first_name": "Foo",
        "last_name": "Bar",
        "email": "atorresj@redhat.com",
    }


@pytest.fixture
def test_user_dict_no_account():
    return {
        "username": "foo",
        "first_name": "Foo",
        "last_name": "Bar",
        "email": "foobarbaz@example.com",
    }


@pytest.fixture
def public_source():
    return FlawSource.INTERNET


@pytest.fixture
def private_source():
    return FlawSource.APPLE


@pytest.fixture
def both_source():
    return FlawSource.GENTOO


@pytest.fixture
def fake_integration_settings():
    return IntegrationSettings(vault_addr="foo", role_id="bar", secret_id="baz")


@pytest.fixture
def fake_integration_repo(fake_integration_settings):
    return IntegrationRepository(fake_integration_settings)


@pytest.fixture
def mock_hvac_client_instance():
    """Creates a MagicMock instance for hvac.Client."""
    return MagicMock()


@pytest.fixture(autouse=True)
def patch_hvac_client(monkeypatch, mock_hvac_client_instance):
    """Patches hvac.Client in vault_integration module to return our mock instance."""
    MockHvacClientClass = MagicMock(return_value=mock_hvac_client_instance)
    monkeypatch.setattr("osidb.integrations.hvac.Client", MockHvacClientClass)
    # Note: Credentials are set per-test via set_hvac_test_env_vars fixture or fake_integration_settings
    return MockHvacClientClass


@pytest.fixture
def set_hvac_test_env_vars():
    """Set Vault credentials as environment variables for tests."""
    os.environ["OSIDB_VAULT_ADDR"] = "https://fake-vault:8200/"
    os.environ["OSIDB_ROLE_ID"] = "fake-role"
    os.environ["OSIDB_SECRET_ID"] = "fake-secret"

    yield

    # Clean up to prevent leaking to other tests
    os.environ.pop("OSIDB_VAULT_ADDR", None)
    os.environ.pop("OSIDB_ROLE_ID", None)
    os.environ.pop("OSIDB_SECRET_ID", None)


# Fixtures for relative datetime filtering tests


@pytest.fixture
@freeze_time("2024-06-15 12:00:00")
def affects_at_different_times():
    """Create affects at different times for testing relative datetime filters"""
    flaw = FlawFactory(embargoed=False)

    return {
        "flaw": flaw,
        "affect_5_hours_ago": AffectFactory(
            flaw=flaw,
            created_dt=django_timezone.now() - django_timezone.timedelta(hours=5),
        ),
        "affect_2_hours_ago": AffectFactory(
            flaw=flaw,
            created_dt=django_timezone.now() - django_timezone.timedelta(hours=2),
        ),
        "affect_30_min_ago": AffectFactory(
            flaw=flaw,
            created_dt=django_timezone.now() - django_timezone.timedelta(minutes=30),
        ),
    }


@pytest.fixture
@freeze_time("2024-06-15 12:00:00")
def trackers_at_different_times():
    """Create trackers at different times for testing relative datetime filters"""
    ps_module = PsModuleFactory(bts_name="bugzilla")
    ps_stream = PsUpdateStreamFactory(ps_module=ps_module)
    flaw = FlawFactory(embargoed=False)
    affect = AffectFactory(
        flaw=flaw,
        ps_module=ps_module.name,
        ps_update_stream=ps_stream.name,
        affectedness=Affect.AffectAffectedness.AFFECTED,
        resolution=Affect.AffectResolution.DELEGATED,
    )

    return {
        "tracker_3_days_ago": TrackerFactory(
            type=Tracker.TrackerType.BUGZILLA,
            affects=[affect],
            ps_update_stream=ps_stream.name,
            created_dt=django_timezone.now() - django_timezone.timedelta(days=3),
        ),
        "tracker_1_day_ago": TrackerFactory(
            type=Tracker.TrackerType.BUGZILLA,
            affects=[affect],
            ps_update_stream=ps_stream.name,
            created_dt=django_timezone.now() - django_timezone.timedelta(days=1),
        ),
        "tracker_2_hours_ago": TrackerFactory(
            type=Tracker.TrackerType.BUGZILLA,
            affects=[affect],
            ps_update_stream=ps_stream.name,
            created_dt=django_timezone.now() - django_timezone.timedelta(hours=2),
        ),
    }


@pytest.fixture
@freeze_time("2024-06-15 12:00:00")
def flaws_at_different_update_times():
    """Create flaws with different updated_dt for testing changed_after and changed_before"""
    return {
        "flaw_3_days_ago": FlawFactory(
            embargoed=False,
            local_updated_dt=django_timezone.now() - django_timezone.timedelta(days=3),
            updated_dt=django_timezone.now() - django_timezone.timedelta(days=3),
        ),
        "flaw_1_day_ago": FlawFactory(
            embargoed=False,
            local_updated_dt=django_timezone.now() - django_timezone.timedelta(days=1),
            updated_dt=django_timezone.now() - django_timezone.timedelta(days=1),
        ),
        "flaw_2_hours_ago": FlawFactory(
            embargoed=False,
            local_updated_dt=django_timezone.now() - django_timezone.timedelta(hours=2),
            updated_dt=django_timezone.now() - django_timezone.timedelta(hours=2),
        ),
    }
