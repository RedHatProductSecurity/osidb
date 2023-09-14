import pytest

from apps.trackers.constants import TRACKERS_API_VERSION
from osidb.models import Tracker


@pytest.fixture(autouse=True)
def use_debug(settings) -> str:
    """Enforce DEBUG=True in all tests because pytest hardcodes it to False

    See: https://github.com/pytest-dev/pytest-django/pull/463

    Once the `--django-debug-mode` option is added to pytest, we can get rid of this fixture and
    use the CLI setting via pytest.ini:
    https://docs.pytest.org/en/latest/customize.html#adding-default-options
    """
    settings.DEBUG = True


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db) -> None:
    pass


@pytest.fixture(autouse=True)
def pin_urls(monkeypatch) -> None:
    """
    the tests should be immune to what .evn you build the testrunner with
    """
    monkeypatch.setenv("HTTPS_PROXY", "http://squid.corp.redhat.com:3128")


@pytest.fixture
def jira_test_url() -> str:
    return "https://issues.stage.redhat.com"


@pytest.fixture
def user_token() -> str:
    return "USER_JIRA_TOKEN"


@pytest.fixture
def stage_jira_project() -> str:
    return "OSIM"


@pytest.fixture
def test_app_scheme_host() -> str:
    return "http://osidb-service:8000/trackers"


@pytest.fixture
def api_version() -> str:
    return TRACKERS_API_VERSION


@pytest.fixture
def test_app_api_uri(test_app_scheme_host, api_version) -> str:
    return f"{test_app_scheme_host}/api/{api_version}"


@pytest.fixture
def fake_triage() -> None:
    """
    fake triage tracker property to be always True
    """
    is_triage = getattr(Tracker, "is_triage")
    setattr(Tracker, "is_triage", property(lambda self: True))
    yield
    # cleanup after the test run
    setattr(Tracker, "is_triage", is_triage)


@pytest.fixture
def enable_bugzilla_sync(monkeypatch) -> None:
    """
    enable the sync to Bugzilla
    """
    import osidb.models as models

    monkeypatch.setattr(models, "SYNC_TO_BZ", True)


@pytest.fixture
def enable_jira_sync(monkeypatch) -> None:
    """
    enable the sync to Jira
    """
    import osidb.models as models

    monkeypatch.setattr(models, "SYNC_TO_JIRA", True)
