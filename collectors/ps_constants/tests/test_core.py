import pytest

from collectors.ps_constants.core import (
    fetch_ps_constants,
    sync_compliance_priority,
    sync_special_consideration_packages,
    sync_ubi_packages,
)
from osidb.models import CompliancePriority, SpecialConsiderationPackage, UbiPackage

pytestmark = pytest.mark.unit


class TestPsConstantsCollection:
    @pytest.mark.vcr
    def test_fetch_ps_constants(self, ps_constant_base_url):
        """Check collector is capable of pull data from gitlab"""
        url = "/".join((ps_constant_base_url, "compliance_priority.yml"))
        compliance_priority = fetch_ps_constants(url)
        assert "rhel-9" in compliance_priority
        assert len(compliance_priority["rhel-9"]) > 0

        url = "/".join((ps_constant_base_url, "ubi_packages.yml"))
        ubi_packages = fetch_ps_constants(url)
        assert "rhel-9" in ubi_packages
        assert len(ubi_packages["rhel-9"]) > 0

        url = "/".join((ps_constant_base_url, "special_consideration_packages.yml"))
        sc_packages = fetch_ps_constants(url)
        assert "dnf" in sc_packages

    def test_sync_compliance_priority(self):
        """
        test collector compliance priority data sync
        """
        sampled_data = {
            "rhel-1": [
                "test-package",
                "another-package",
            ],
            "rhel-2": [
                "test-package",
                "another-package",
            ],
        }
        sync_compliance_priority(sampled_data)

        assert CompliancePriority.objects.all().count() == 4
        assert CompliancePriority.objects.filter(ps_module="rhel-1").count() == 2
        assert (
            CompliancePriority.objects.filter(ps_component="test-package").count() == 2
        )

    def test_sync_ubi_packages(self):
        """Check collector can correctly sync ubi data in database"""
        sampled_data = {
            "rhel-1": [
                "test-package",
                "another-package",
            ],
            "rhel-2": [
                "test-package",
                "another-package",
            ],
        }
        sync_ubi_packages(sampled_data)

        assert UbiPackage.objects.all().count() == 4
        assert UbiPackage.objects.filter(major_stream_version="rhel-1").count() == 2
        assert UbiPackage.objects.filter(name="test-package").count() == 2

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
