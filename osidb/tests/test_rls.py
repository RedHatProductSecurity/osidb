import pytest
from django.conf import settings
from django.db import transaction
from django.db.utils import ProgrammingError

from osidb.core import set_user_acls
from osidb.models import CVSS, Flaw, Impact
from osidb.tests.factories import FlawCVSSFactory, FlawFactory

pytestmark = pytest.mark.enable_rls


class TestRLS:
    # XXX: The following tests use Flaw for a model to test ACLs on,
    # but any RLS-enabled model should be able to replace Flaw and
    # make the tests pass.
    @pytest.mark.parametrize(
        "embargoed,acls",
        [
            (False, settings.PUBLIC_READ_GROUPS + [settings.PUBLIC_WRITE_GROUP]),
            (True, [settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP]),
        ],
    )
    def test_create_flaw(self, embargoed, acls):
        """
        Test that creating a Flaw only works if the correct ACLs are set.
        """
        with transaction.atomic():
            with pytest.raises(
                ProgrammingError, match="violates row-level security policy"
            ):
                FlawFactory(embargoed=embargoed)
        set_user_acls(acls)
        assert FlawFactory(embargoed=embargoed)

    @pytest.mark.parametrize(
        "embargoed,acls",
        [
            (False, settings.PUBLIC_READ_GROUPS + [settings.PUBLIC_WRITE_GROUP]),
            (True, [settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP]),
        ],
    )
    def test_read_flaw(self, embargoed, acls):
        """
        Test that reading a Flaw only works if the correct ACLs are set.
        """
        assert Flaw.objects.count() == 0

        set_user_acls(acls)
        f = FlawFactory(embargoed=embargoed)
        assert f

        # set to read-only
        set_user_acls(acls[:1])
        assert Flaw.objects.count() == 1
        assert f.uuid == Flaw.objects.first().uuid

    def test_read_multiple_flaw(self):
        """
        Test that members of one group cannot read objects from another's.
        """
        assert Flaw.objects.count() == 0

        set_user_acls(settings.ALL_GROUPS)
        f_public_uuid = FlawFactory(embargoed=False).uuid
        f_embargo_uuid = FlawFactory(embargoed=True).uuid
        assert Flaw.objects.count() == 2

        set_user_acls(settings.PUBLIC_READ_GROUPS)
        assert Flaw.objects.count() == 1
        assert Flaw.objects.first().uuid == f_public_uuid

        set_user_acls([settings.EMBARGO_READ_GROUP])
        assert Flaw.objects.count() == 1
        assert Flaw.objects.first().uuid == f_embargo_uuid

    def test_update_flaw(self):
        """
        Test that updating a Flaw works if the correct ACLs are set.
        """
        set_user_acls(settings.ALL_GROUPS)
        f1 = FlawFactory(title="foo", embargoed=False)
        f2 = FlawFactory(title="bar", embargoed=True, impact=Impact.MODERATE)
        # Avoid issuing alerts for f2 so that the error is not due to the RLS in the alert table
        FlawCVSSFactory(
            flaw=f2,
            version=CVSS.CVSSVersion.VERSION3,
            issuer=CVSS.CVSSIssuer.REDHAT,
            vector="CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H",
        )

        set_user_acls(settings.PUBLIC_READ_GROUPS + [settings.PUBLIC_WRITE_GROUP])
        f1.title = "baz"
        f1.save(raise_validation_error=False)
        assert f1.title == "baz"
        f2.title = "quux"

        with transaction.atomic():
            with pytest.raises(
                Flaw.DoesNotExist, match="Flaw matching query does not exist."
            ):
                f2.save(raise_validation_error=False)

        set_user_acls([settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP])
        f2 = Flaw.objects.first()
        f2.title = "quux"
        f2.save(raise_validation_error=False)
        assert f2.title == "quux"

    def test_delete_flaw(self):
        """
        Test that deleting a Flaw works if the correct ACLs are set.
        """
        set_user_acls(settings.ALL_GROUPS)
        f1 = FlawFactory(title="foo", embargoed=False)
        f2 = FlawFactory(title="bar", embargoed=True)

        set_user_acls(settings.PUBLIC_READ_GROUPS + [settings.PUBLIC_WRITE_GROUP])
        assert Flaw.objects.count() == 1
        assert f1.delete()
        assert Flaw.objects.count() == 0

        with transaction.atomic():
            with pytest.raises(
                Flaw.DoesNotExist, match="Flaw matching query does not exist."
            ):
                Flaw.objects.get(pk=f2.uuid).delete()

        set_user_acls([settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP])
        assert Flaw.objects.count() == 1
        assert Flaw.objects.get(pk=f2.uuid).delete()
        assert Flaw.objects.count() == 0
