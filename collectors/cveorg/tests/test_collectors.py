from pathlib import Path

import pytest
from django.utils.timezone import datetime, make_aware
from jira.exceptions import JIRAError

from apps.taskman.service import JiraTaskmanQuerier
from collectors.cveorg.collectors import CVEorgCollector, CVEorgCollectorException
from osidb.models import Flaw, Snippet
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.integration


class TestCVEorgCollector:
    @pytest.mark.vcr
    def test_collect_cveorg_records(self, mock_keywords, mock_repo):
        """
        Test that snippets and flaws are created correctly.
        """
        cc = CVEorgCollector()
        cc.snippet_creation_enabled = True
        cc.snippet_creation_start_date = None
        cc.collect()

        assert Snippet.objects.count() == 2
        assert Flaw.objects.count() == 2

        flaw1 = Flaw.objects.get(cve_id="CVE-2024-0181")
        snippet1 = Snippet.objects.get(external_id="CVE-2024-0181")
        assert flaw1
        assert snippet1
        assert snippet1.flaw == flaw1

        flaw2 = Flaw.objects.get(cve_id="CVE-2024-4923")
        snippet2 = Snippet.objects.get(external_id="CVE-2024-4923")
        assert flaw2
        assert snippet2
        assert snippet2.flaw == flaw2

    def test_collect_cveorg_record_when_flaw_exists(self, mock_keywords, mock_repo):
        """
        Test that only a snippet is created when a flaw already exists.
        """
        flaw = FlawFactory(cve_id="CVE-2024-4923")
        assert Flaw.objects.count() == 1
        assert Snippet.objects.count() == 0

        cc = CVEorgCollector()
        cc.snippet_creation_enabled = True
        cc.snippet_creation_start_date = make_aware(datetime(2024, 5, 1))
        cc.collect()

        assert Snippet.objects.count() == 1
        assert Flaw.objects.count() == 1

        snippet = Snippet.objects.first()
        assert snippet.flaw == flaw

    def test_ignored_cveorg_records(self, mock_keywords, mock_repo):
        """
        Test that snippets and flaws are not created when they do not comply with rules.
        """
        # skip creation of flaw complying with rules
        FlawFactory(cve_id="CVE-2024-4923")
        assert Flaw.objects.count() == 1

        cc = CVEorgCollector()
        cc.snippet_creation_enabled = True
        cc.snippet_creation_start_date = make_aware(datetime(2024, 1, 20))
        cc.collect()

        assert Flaw.objects.count() == 1
        assert Flaw.objects.get(cve_id="CVE-2024-4923")

        assert not Flaw.objects.filter(cve_id="CVE-2024-0181")  # historical data
        assert not Flaw.objects.filter(cve_id="CVE-2024-0203")  # not passing keywords
        assert not Flaw.objects.filter(cve_id="CVE-2024-1087")  # rejected flaw

    @pytest.mark.vcr
    @pytest.mark.default_cassette(
        "TestCVEorgCollector.test_collect_cveorg_records.yaml"
    )
    def test_collect_cveorg_record(self, mock_keywords, mock_repo):
        """
        Test that snippet and flaw for a given cve are created correctly.
        """
        cve_id = "CVE-2024-0181"

        cc = CVEorgCollector()
        cc.snippet_creation_enabled = True
        cc.snippet_creation_start_date = None
        result = cc.collect_cve(cve_id)

        assert Snippet.objects.count() == 1
        assert Flaw.objects.count() == 1

        flaw = Flaw.objects.get(cve_id=cve_id)
        snippet = Snippet.objects.get(external_id=cve_id)
        assert flaw
        assert snippet
        assert snippet.flaw == flaw
        assert result == f"Flaw for {cve_id} was created successfully."


class TestCVEorgCollectorException:

    repo_path = Path(__file__).resolve().parent

    def test_fail_clone_repo(self, monkeypatch):
        """
        Test that flaw and snippet are not created if the cvelistV5 repository was not created.
        """

        def clone_repo(self):
            raise CVEorgCollectorException

        monkeypatch.setattr(CVEorgCollector, "REPO_PATH", self.repo_path)
        monkeypatch.setattr(CVEorgCollector, "clone_repo", clone_repo)

        cc = CVEorgCollector()
        cc.snippet_creation_enabled = True
        cc.snippet_creation_start_date = None

        with pytest.raises(CVEorgCollectorException):
            cc.collect()

        assert Snippet.objects.all().count() == 0
        assert Flaw.objects.all().count() == 0

    def test_fail_update_repo(self, monkeypatch):
        """
        Test that flaw and snippet are not created if the cvelistV5 repository was not updated.
        """

        def clone_repo(self):
            return

        def update_repo(self):
            raise CVEorgCollectorException

        monkeypatch.setattr(CVEorgCollector, "REPO_PATH", self.repo_path)
        monkeypatch.setattr(CVEorgCollector, "clone_repo", clone_repo)
        monkeypatch.setattr(CVEorgCollector, "update_repo", update_repo)

        cc = CVEorgCollector()
        cc.snippet_creation_enabled = True
        cc.snippet_creation_start_date = None

        with pytest.raises(CVEorgCollectorException):
            cc.collect()

        assert Snippet.objects.all().count() == 0
        assert Flaw.objects.all().count() == 0

    def test_fail_get_repo_changes(self, monkeypatch):
        """
        Test that flaw and snippet are not created if the cvelistV5 repository changes were not fetched.
        """

        def clone_repo(self):
            return

        def update_repo(self):
            return

        def get_repo_changes(self):
            raise CVEorgCollectorException

        monkeypatch.setattr(CVEorgCollector, "REPO_PATH", self.repo_path)
        monkeypatch.setattr(CVEorgCollector, "clone_repo", clone_repo)
        monkeypatch.setattr(CVEorgCollector, "update_repo", update_repo)
        monkeypatch.setattr(CVEorgCollector, "get_repo_changes", get_repo_changes)

        cc = CVEorgCollector()
        cc.snippet_creation_enabled = True
        cc.snippet_creation_start_date = None

        with pytest.raises(CVEorgCollectorException):
            cc.collect()

        assert Snippet.objects.all().count() == 0
        assert Flaw.objects.all().count() == 0

    def test_fail_get_cve_file_path(self, monkeypatch):
        """
        Test that flaw and snippet are not created if the cvelistV5 repository
        does not contain exactly one file path for a given cve.
        """

        def clone_repo(self):
            return

        def update_repo(self):
            return

        def get_cve_file_path(self, cve="CVE-2024-0181"):
            raise CVEorgCollectorException

        monkeypatch.setattr(CVEorgCollector, "REPO_PATH", self.repo_path)
        monkeypatch.setattr(CVEorgCollector, "clone_repo", clone_repo)
        monkeypatch.setattr(CVEorgCollector, "update_repo", update_repo)
        monkeypatch.setattr(CVEorgCollector, "get_cve_file_path", get_cve_file_path)

        cc = CVEorgCollector()
        cc.snippet_creation_enabled = True
        cc.snippet_creation_start_date = None

        with pytest.raises(CVEorgCollectorException):
            cc.collect_cve("CVE-2024-0181")

        assert Snippet.objects.all().count() == 0
        assert Flaw.objects.all().count() == 0

    def test_atomicity(self, monkeypatch, mock_keywords, mock_repo):
        """
        Test that flaw and snippet are not created if any error occurs during the flaw creation.
        """

        def mock_create_or_update_task(self, flaw):
            raise JIRAError(status_code=401)

        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", mock_create_or_update_task
        )

        cc = CVEorgCollector()
        cc.snippet_creation_enabled = True
        cc.snippet_creation_start_date = make_aware(datetime(2024, 5, 1))

        with pytest.raises(CVEorgCollectorException):
            cc.collect()

        assert Snippet.objects.all().count() == 0
        assert Flaw.objects.all().count() == 0
