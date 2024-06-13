import uuid

import pytest
from django.conf import settings

from osidb.core import generate_acls
from osidb.tests.factories import FlawFactory


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture
def test_flaw():
    return FlawFactory(bz_id="2011264")


@pytest.fixture
def sentinel_err_message():
    return "400 Client Error: Bad Request"


@pytest.fixture
def internal_read_groups():
    return [uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_READ_GROUP])]


@pytest.fixture
def internal_write_groups():
    return [uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_WRITE_GROUP])]


@pytest.fixture(autouse=True)
def pin_envs(monkeypatch) -> None:
    """
    the tests should be immune to what .env you build the testrunner with
    """
    import apps.taskman.mixins as task_mixins
    import osidb.models as models
    import osidb.serializer as serializer

    monkeypatch.setattr(task_mixins, "JIRA_TASKMAN_AUTO_SYNC_FLAW", False)
    monkeypatch.setattr(models, "JIRA_TASKMAN_AUTO_SYNC_FLAW", False)
    monkeypatch.setattr(serializer, "JIRA_TASKMAN_AUTO_SYNC_FLAW", False)
