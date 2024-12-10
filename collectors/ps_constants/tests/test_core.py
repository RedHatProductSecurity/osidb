import pytest

from apps.trackers.models import JiraBugIssuetype
from collectors.cveorg.models import Keyword
from collectors.ps_constants.core import (
    fetch_ps_constants,
    sync_cveorg_keywords,
    sync_jira_bug_issuetype,
    sync_special_consideration_packages,
)
from osidb.models import SpecialConsiderationPackage

pytestmark = pytest.mark.unit


SAMPLE_JIRA_BUG_ISSUETYPE = {
    "bug_issuetype": [
        "PROJ1",
        "PROJ2",
        "PROJ3",
        "PROJ3",  # Simulate a bug in source data with duplicated project
    ]
}


class TestPsConstantsCollection:
    @pytest.mark.vcr
    def test_fetch_ps_constants(self, ps_constant_base_url):
        """Check collector is capable of pull data from gitlab"""
        url = "/".join((ps_constant_base_url, "special_consideration_packages.yml"))
        sc_packages = fetch_ps_constants(url)
        assert "dnf" in sc_packages

        keywords_url = f"{ps_constant_base_url}/cveorg_keywords.yml"
        keywords = fetch_ps_constants(keywords_url)
        assert len(keywords) == 4
        assert [*keywords.keys()] == [
            "allowlist",
            "allowlist_special_cases",
            "blocklist",
            "blocklist_special_cases",
        ]

        # TODO: Record cassette for jira_bug_issuetype, tracked in OSIDB-2980

    def test_sync_special_consideration_packages(self):
        """
        Check collector can correctly sync special
        consideration packages data in database
        """
        sampled_data = ["test-package", "another-package"]

        sync_special_consideration_packages(sampled_data)

        assert SpecialConsiderationPackage.objects.all().count() == 2
        assert (
            SpecialConsiderationPackage.objects.filter(name="test-package").count() == 1
        )
        assert (
            SpecialConsiderationPackage.objects.filter(name="another-package").count()
            == 1
        )

    def test_sync_jira_bug_issuetype(self):
        assert JiraBugIssuetype.objects.count() == 0

        sync_jira_bug_issuetype(SAMPLE_JIRA_BUG_ISSUETYPE)

        assert JiraBugIssuetype.objects.count() == 3
        assert sorted(JiraBugIssuetype.objects.values_list("project", flat=True)) == [
            "PROJ1",
            "PROJ2",
            "PROJ3",
        ]

    def test_sync_cveorg_keywords(self):
        """
        Test that CVEorg keywords are correctly synced in the database.
        """
        mock_keywords = {
            "allowlist": ["kernel"],
            "allowlist_special_cases": [r"(?:\W|^)\.NET\b"],
            "blocklist": [".*plugin.*for WordPress", "Cisco", "IBM Tivoli", "iTunes"],
            "blocklist_special_cases": ["iOS"],
        }

        sync_cveorg_keywords(mock_keywords)

        assert Keyword.objects.filter(type=Keyword.Type.ALLOWLIST).count() == 1
        assert (
            Keyword.objects.filter(type=Keyword.Type.ALLOWLIST_SPECIAL_CASE).count()
            == 1
        )
        assert Keyword.objects.filter(type=Keyword.Type.BLOCKLIST).count() == 4
        assert (
            Keyword.objects.filter(type=Keyword.Type.BLOCKLIST_SPECIAL_CASE).count()
            == 1
        )

    def test_failed_sync_cveorg_keywords(self):
        """
        Test that CVEorg keywords without expected groups raise an error.
        """
        mock_keywords = {
            "allowlist": ["kernel"],
            "allowlist_special_cases": [r"(?:\W|^)\.NET\b"],
            "blocklist": [".*plugin.*for WordPress", "Cisco", "IBM Tivoli", "iTunes"],
            # "blocklist_special_cases" is missing
        }

        with pytest.raises(KeyError):
            sync_cveorg_keywords(mock_keywords)

        assert Keyword.objects.count() == 0
