import pytest
from django.core.exceptions import ValidationError

from osidb.models import Package, PackageVer
from osidb.tests.factories import PackageFactory, PackageVerFactory

pytestmark = pytest.mark.unit


class TestPackageVersions(object):
    def test_create_cve_v5_version(self):
        """test raw verison range creation"""

        pkg = PackageFactory.create()

        vr_2 = PackageVer.objects.create(
            version="3.2.1",
            package=pkg,
        )

        assert vr_2.validate() is None
        assert vr_2.save() is None

    def test_create_cve_v5_package_versions(self):

        vrs_1 = Package()
        with pytest.raises(ValidationError):
            vrs_1.validate()

        vrs_2 = PackageFactory.create()
        PackageVerFactory(package=vrs_2)

        assert vrs_2.validate() is None
        assert vrs_2.save() is None
