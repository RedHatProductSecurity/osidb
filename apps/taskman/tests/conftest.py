import uuid

import pytest
from django.conf import settings
from taskman.constants import TASKMAN_API_VERSION


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
    return "USER_JIRA_TOKEN"


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
def pin_urls(monkeypatch) -> None:
    """
    the tests should be immune to what .evn you build the testrunner with
    """
    monkeypatch.setenv("HTTPS_PROXY", "http://squid.corp.redhat.com:3128")
    monkeypatch.setenv("JIRA_TASKMAN_URL", "https://issues.stage.redhat.com")


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
