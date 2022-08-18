import uuid
from datetime import datetime, timezone

import pytest
from django.conf import settings

from osidb.constants import OSIDB_API_VERSION
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
def test_ps_module():
    from osidb.tests.factories import PsModuleFactory

    PsModuleFactory(name="rhel-6")


@pytest.fixture
def root_url():
    return "http://osdib-service:8000"


@pytest.fixture
def test_scheme_host():
    return "http://osidb-service:8000/osidb"


@pytest.fixture
def api_version():
    return OSIDB_API_VERSION


@pytest.fixture
def test_api_uri(test_scheme_host, api_version):
    return f"{test_scheme_host}/api/{api_version}"


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
    return "CVE-1970-101010"


@pytest.fixture
def good_cve_id2():
    return "CVE-2021-999999"


@pytest.fixture
def public_read_group():
    return generate_acls(settings.PUBLIC_READ_GROUPS)


@pytest.fixture
def embargo_read_group():
    return generate_acls([settings.EMBARGO_READ_GROUP])


@pytest.fixture
def public_groups(public_read_group):
    return [uuid.UUID(acl) for acl in public_read_group]


@pytest.fixture
def embargoed_groups(embargo_read_group):
    return [uuid.UUID(acl) for acl in embargo_read_group]


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
