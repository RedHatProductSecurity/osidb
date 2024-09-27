import pytest

import apps.bbsync.constants as bbsync_constants
import apps.trackers.common as common
import osidb.models as models
import osidb.serializer as serializer
from apps.sla.framework import SLAPolicy
from apps.trackers.constants import TRACKERS_API_VERSION


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
def pin_envs(monkeypatch) -> None:
    """
    the tests should be immune to what .env you build the testrunner with
    """
    monkeypatch.setattr(common, "BZ_URL", "https://example.com")

    # Mock settings that use the code path actually used in production at the
    # time of writing test_tracker_create_update_jira_vulnerability_issuetype (2024-09).
    monkeypatch.setattr(models, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
    monkeypatch.setattr(serializer, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
    monkeypatch.setattr(bbsync_constants, "SYNC_FLAWS_TO_BZ_ASYNCHRONOUSLY", True)
    monkeypatch.setattr(models, "SYNC_FLAWS_TO_BZ_ASYNCHRONOUSLY", True)


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


@pytest.fixture()
def clean_policies():
    """
    clean SLA framework before and after every test

        * before so it is not mixed with some leftovers
        * after so we do not leave any leftovers

    if we do it only before or only after the tests might behave differently
    when run in batch than when run alone so better to be safe then sorry
    """
    SLAPolicy.objects.all().delete()
    yield  # run test here
    SLAPolicy.objects.all().delete()
