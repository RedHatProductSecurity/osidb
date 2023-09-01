import pytest
from django.core.exceptions import ValidationError

from osidb.models import Package, PackageVer
from osidb.tests.factories import FlawFactory, PackageFactory, PackageVerFactory

pytestmark = pytest.mark.unit


class TestPackageVersions(object):
    def test_create_cve_v5_version(self):
        """test raw verison range creation"""

        generate_fake_acls = FlawFactory()
        pkg = PackageFactory(
            acl_read=generate_fake_acls.acl_read,
            acl_write=generate_fake_acls.acl_write,
        )

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

        vrs_2 = PackageFactory()
        PackageVerFactory(package=vrs_2)

        assert vrs_2.validate() is None
        assert vrs_2.save() is None
