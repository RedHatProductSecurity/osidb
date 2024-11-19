import pytest


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture(autouse=True)
def auto_enable_sync(enable_jira_task_sync, enable_bz_sync) -> None:
    pass
