from pathlib import Path

import pytest
from django.utils import timezone

import apps.bbsync.mixins as bbsync_mixins
import apps.taskman.mixins as taskman_mixins
import osidb.models.flaw.flaw as flaw_module
from collectors.cveorg import collectors
from collectors.cveorg.collectors import CVEorgCollector


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture(autouse=True)
def enable_env_vars(monkeypatch) -> None:
    """
    Set necessary variables when storing flaws to BZ and Jira.
    """
    monkeypatch.setattr(bbsync_mixins, "SYNC_TO_BZ", True)
    monkeypatch.setattr(collectors, "JIRA_AUTH_TOKEN", "SECRET")
    monkeypatch.setattr(flaw_module, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
    monkeypatch.setattr(flaw_module, "SYNC_FLAWS_TO_BZ", True)
    monkeypatch.setattr(taskman_mixins, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)


@pytest.fixture()
def mock_repo(monkeypatch) -> None:
    """
    Set testing data and variables to mock the cvelistV5 repository.
    """
    repo_path = f"{Path(__file__).resolve().parent}/cvelistV5"
    cve_path = r"CVE-(?:1999|2\d{3})-(?!0{4})(?:0\d{3}|[1-9]\d{3,}).json$"

    def clone_repo(self):
        return

    def update_repo(self):
        return

    def get_repo_changes(self):
        stdout = "CVE-2024-0181.json\nCVE-2024-0203.json\nCVE-2024-1087.json\nCVE-2024-4923.json\n"
        period_end = timezone.datetime(
            2024, 7, 1, tzinfo=timezone.get_current_timezone()
        )
        return stdout, period_end

    monkeypatch.setattr(CVEorgCollector, "REPO_PATH", repo_path)
    monkeypatch.setattr(CVEorgCollector, "CVE_PATH", cve_path)
    monkeypatch.setattr(CVEorgCollector, "clone_repo", clone_repo)
    monkeypatch.setattr(CVEorgCollector, "update_repo", update_repo)
    monkeypatch.setattr(CVEorgCollector, "get_repo_changes", get_repo_changes)
