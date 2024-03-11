import uuid

import pytest
from django.conf import settings
from taskman.constants import JIRA_AUTH_TOKEN, TASKMAN_API_VERSION

import apps.taskman.service as service
from osidb.constants import OSIDB_API_VERSION


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
def user_token():
    return JIRA_AUTH_TOKEN if JIRA_AUTH_TOKEN else "USER_JIRA_TOKEN"


@pytest.fixture
def bz_api_key():
    return "USER_BZ_API_KEY"


@pytest.fixture
def test_scheme_host():
    return "http://osidb-service:8000/taskman"


@pytest.fixture
def api_version():
    return TASKMAN_API_VERSION


@pytest.fixture
def test_api_uri(test_scheme_host, api_version):
    return f"{test_scheme_host}/api/{api_version}"


@pytest.fixture(autouse=True)
def pin_envs(monkeypatch) -> None:
    """
    the tests should be immune to what .env you build the testrunner with
    """
    monkeypatch.setenv("HTTPS_PROXY", "http://squid.corp.redhat.com:3128")
    monkeypatch.setenv("JIRA_TASKMAN_URL", "https://example.com/")
    monkeypatch.setenv("JIRA_TASKMAN_AUTO_SYNC_FLAW", "1")
    monkeypatch.setattr(service, "JIRA_TASKMAN_URL", "https://example.com")


@pytest.fixture
def acl_read():
    return [
        uuid.uuid5(uuid.NAMESPACE_URL, f"https://osidb.prod.redhat.com/ns/acls#{group}")
        for group in settings.PUBLIC_READ_GROUPS
    ]


@pytest.fixture
def acl_write():
    return [
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"https://osidb.prod.redhat.com/ns/acls#{settings.PUBLIC_WRITE_GROUP}",
        )
    ]


@pytest.fixture
def test_osidb_scheme_host():
    return "http://osidb-service:8000/osidb"


@pytest.fixture
def osidb_api_version():
    return OSIDB_API_VERSION


@pytest.fixture
def test_osidb_api_uri(test_osidb_scheme_host, osidb_api_version):
    return f"{test_osidb_scheme_host}/api/{osidb_api_version}"
