import uuid

import pytest
from django.conf import settings

from osidb.core import generate_acls


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture(autouse=True)
def enable_env_vars(monkeypatch) -> None:
    import apps.bbsync.mixins as bbsync_mixins
    import apps.taskman.mixins as taskman_mixins
    import osidb.dmodels.tracker as tracker
    from collectors.nvd import collectors
    from osidb import models

    monkeypatch.setattr(bbsync_mixins, "SYNC_TO_BZ", True)
    monkeypatch.setattr(taskman_mixins, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
    monkeypatch.setattr(models, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
    monkeypatch.setattr(models, "SYNC_FLAWS_TO_BZ", True)
    monkeypatch.setattr(tracker, "SYNC_TRACKERS_TO_BZ", True)
    monkeypatch.setattr(collectors, "JIRA_AUTH_TOKEN", "SECRET")


@pytest.fixture
def internal_read_groups():
    return [uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_READ_GROUP])]


@pytest.fixture
def internal_write_groups():
    return [uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_WRITE_GROUP])]
