import pytest
from django.core.exceptions import ValidationError

from osidb.models import CVEv5PackageVersions, CVEv5Version, VersionStatus
from osidb.tests.factories import CVEv5PackageVersionsFactory, CVEv5VersionFactory

pytestmark = pytest.mark.unit


class TestPackageVersions(object):
    def test_create_cve_v5_version(self):
        """test raw verison range creation"""

        vr_1 = CVEv5Version.objects.create(
            version="3.2.1",
        )

        with pytest.raises(ValidationError):
            vr_1.validate()

        vr_2 = CVEv5Version.objects.create(
            version="3.2.1",
            status=VersionStatus.UNAFFECTED,
        )

        assert vr_2.validate() is None
        assert vr_2.save() is None

    def test_create_cve_v5_package_versions(self):

        vrs_1 = CVEv5PackageVersions()
        with pytest.raises(ValidationError):
            vrs_1.validate()

        vr_1 = CVEv5VersionFactory()

        vrs_2 = CVEv5PackageVersionsFactory.create(versions=(vr_1,))

        assert vrs_2.validate() is None
        assert vrs_2.save() is None
