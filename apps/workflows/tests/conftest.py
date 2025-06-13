import os
from unittest.mock import MagicMock

import pytest

from apps.workflows.constants import WORKFLOWS_API_VERSION
from apps.workflows.workflow import WorkflowFramework
from osidb.helpers import get_env


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
def ldap_test_username():
    return "testuser"


@pytest.fixture
def ldap_test_password():
    return "password"


@pytest.fixture
def test_scheme_host():
    return "http://osidb-service:8000/workflows"


@pytest.fixture
def test_scheme_host_osidb():
    return "http://osidb-service:8000/osidb"


@pytest.fixture
def api_version():
    return WORKFLOWS_API_VERSION


@pytest.fixture
def test_api_uri(test_scheme_host, api_version):
    return f"{test_scheme_host}/api/{api_version}"


@pytest.fixture
def test_api_uri_osidb(test_scheme_host_osidb, api_version):
    return f"{test_scheme_host_osidb}/api/{api_version}"


@pytest.fixture
def command_curl():
    """define path to curl"""
    test_curl_path = get_env("TEST_CURL_PATH")
    if test_curl_path is not None:
        return test_curl_path
    return "/usr/bin/curl"


@pytest.fixture(autouse=True)
def clean_workflows():
    """
    clean workflow framework before and after every test

        * before so it is not mixed with some leftovers
        * after so we do not leave any leftovers

    if we do it only before or only after the tests might behave differently
    when run in batch than when run alone so better to be safe then sorry
    """
    workflow_framework = WorkflowFramework()
    workflow_framework._workflows = []
    yield  # run test here
    workflow_framework._workflows = []


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
