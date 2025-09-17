import uuid

import pytest
from django.conf import settings

from collectors.bzimport.collectors import BugzillaTrackerCollector
from osidb.core import generate_acls


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
def bz_bug_id():
    return 607812


@pytest.fixture
def bz_bug_cve_id():
    # corresponding cve_id of the bz bug just above
    return "CVE-2010-2239"


@pytest.fixture
def bz_tracker_id():
    return 619104


@pytest.fixture
def bz_tracker_collector():
    return BugzillaTrackerCollector()


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
