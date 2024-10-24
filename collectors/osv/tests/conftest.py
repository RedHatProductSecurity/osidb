import pytest


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture(autouse=True)
def enable_env_vars(enable_jira_task_sync, enable_bz_sync, monkeypatch) -> None:
    from collectors.osv import collectors

    monkeypatch.setattr(collectors, "JIRA_AUTH_TOKEN", "SECRET")
