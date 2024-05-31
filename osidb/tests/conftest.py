import uuid
from datetime import datetime, timezone

import pytest
from django.conf import settings

from osidb.core import generate_acls
from osidb.helpers import get_env
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


@pytest.fixture(autouse=True)
def pin_envs(monkeypatch) -> None:
    """
    the tests should be immune to what .env you build the testrunner with
    """
    monkeypatch.setenv("BBSYNC_SYNC_TO_BZ", "0")
    monkeypatch.setenv("JIRA_TASKMAN_AUTO_SYNC_FLAW", "0")


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
def public_read_groups():
    return [uuid.UUID(acl) for acl in generate_acls(settings.PUBLIC_READ_GROUPS)]


@pytest.fixture
def embargoed_read_groups():
    return [uuid.UUID(acl) for acl in generate_acls([settings.EMBARGO_READ_GROUP])]


@pytest.fixture
def internal_read_groups():
    return [uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_READ_GROUP])]


@pytest.fixture
def public_write_groups():
    return [uuid.UUID(acl) for acl in generate_acls([settings.PUBLIC_WRITE_GROUP])]


@pytest.fixture
def embargoed_write_groups():
    return [uuid.UUID(acl) for acl in generate_acls([settings.EMBARGO_WRITE_GROUP])]


@pytest.fixture
def internal_write_groups():
    return [uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_WRITE_GROUP])]


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


@pytest.fixture(autouse=True)
def disable_sync(monkeypatch) -> None:
    """
    disable the sync to Bugzilla and Jira
    """
    import apps.bbsync.mixins as mixins
    import osidb.models as models

    monkeypatch.setattr(mixins, "SYNC_TO_BZ", False)
    monkeypatch.setattr(models, "JIRA_TASKMAN_AUTO_SYNC_FLAW", False)
    monkeypatch.setattr(models, "SYNC_FLAWS_TO_BZ", False)
    monkeypatch.setattr(models, "SYNC_TRACKERS_TO_BZ", False)
    monkeypatch.setattr(models, "SYNC_TO_JIRA", False)
