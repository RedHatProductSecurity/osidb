import uuid

import pytest
from django.conf import settings

from osidb.core import generate_acls


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture
def internal_read_groups():
    return [uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_READ_GROUP])]


@pytest.fixture
def internal_write_groups():
    return [uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_WRITE_GROUP])]
