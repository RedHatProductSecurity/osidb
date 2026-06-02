import os
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from osidb.helpers import get_env
from osidb.integrations import IntegrationRepository, IntegrationSettings
from osidb.models import FlawSource


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
    return MockHvacClientClass


@pytest.fixture
def set_hvac_test_env_vars():
    os.environ["OSIDB_VAULT_ADDR"] = "https://fake-vault:8200/"
    os.environ["OSIDB_ROLE_ID"] = "fake-role"
    os.environ["OSIDB_SECRET_ID"] = "fake-secret"
