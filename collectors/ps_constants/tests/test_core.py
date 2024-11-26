import pytest

from apps.trackers.models import JiraBugIssuetype
from collectors.ps_constants.core import (
    fetch_ps_constants,
    sync_jira_bug_issuetype,
    sync_special_consideration_packages,
)
from osidb.models import SpecialConsiderationPackage

pytestmark = pytest.mark.unit


SAMPLE_DATA = {
    "rhel-1": [
        "test1",
        "another1",
    ],
    "rhel-2": [
        "test2",
        "another2",
    ],
}

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
