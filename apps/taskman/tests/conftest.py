import pytest
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
