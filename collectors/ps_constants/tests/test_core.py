import pytest

from collectors.ps_constants.core import (
    fetch_ps_constants,
    sync_compliance_priority,
    sync_contract_priority,
    sync_special_consideration_packages,
    sync_ubi_packages,
)
from osidb.models import (
    CompliancePriority,
    ContractPriority,
    SpecialConsiderationPackage,
    UbiPackage,
)

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

SAMPLE_COMPLIANCE_PRIORITY = {
    "rhel-8": {
        "components": ["acl", "adcli", "attr"],
        "streams": ["rhel-8.6.0.z", "rhel-8.9.0.z"],
    },
    "openshift-4": {
        "components": [
            "cluster-etcd-operator-container",
            "cluster-monitoring-operator-container",
        ],
        "streams": ["rhel-8.6.0.z"],
    },
    "foobar-123": {"streams": ["foo-1", "foo-2"]},
}


class TestPsConstantsCollection:
    @pytest.mark.vcr
    def test_fetch_ps_constants(self, ps_constant_base_url):
        """Check collector is capable of pull data from gitlab"""
        url = "/".join((ps_constant_base_url, "compliance_priority.yml"))
        compliance_priority = fetch_ps_constants(url)
        assert "rhel-8" in compliance_priority
        assert sorted(compliance_priority.keys()) == [
            "fdp-el8-ovs",
            "openshift-4",
            "rhel-8",
        ]

        url = "/".join((ps_constant_base_url, "contract_priority.yml"))
        contract_priority = fetch_ps_constants(url)
        assert "rhel-8" in contract_priority
        assert len(contract_priority["rhel-8"]) > 0

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
        sync_compliance_priority(SAMPLE_COMPLIANCE_PRIORITY)

        assert CompliancePriority.objects.all().count() == 3
        assert CompliancePriority.objects.filter(ps_module="rhel-8").count() == 1
        assert CompliancePriority.objects.filter(ps_module="openshift-4").count() == 1
        assert CompliancePriority.objects.filter(ps_module="foobar-123").count() == 1

        assert CompliancePriority.objects.get(ps_module="rhel-8").streams == [
            "rhel-8.6.0.z",
            "rhel-8.9.0.z",
        ]
        assert CompliancePriority.objects.get(ps_module="openshift-4").streams == [
            "rhel-8.6.0.z"
        ]
        assert CompliancePriority.objects.get(ps_module="foobar-123").streams == [
            "foo-1",
            "foo-2",
        ]

        assert CompliancePriority.objects.get(ps_module="rhel-8").components == [
            "acl",
            "adcli",
            "attr",
        ]
        assert CompliancePriority.objects.get(ps_module="openshift-4").components == [
            "cluster-etcd-operator-container",
            "cluster-monitoring-operator-container",
        ]
        assert CompliancePriority.objects.get(ps_module="foobar-123").components == []

    def test_sync_contract_priority(self):
        """
        test collector contract priority data sync
        """
        # The meaning of SAMPLE_DATA here is {"module": ["update stream"]}.
        sync_contract_priority(SAMPLE_DATA)

        assert ContractPriority.objects.all().count() == 4
        assert ContractPriority.objects.filter(ps_update_stream="test1").count() == 1
        assert ContractPriority.objects.filter(ps_update_stream="test2").count() == 1

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
