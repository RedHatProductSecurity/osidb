import pytest
from django.conf import settings
from django.db import connections, transaction
from django.db.utils import ProgrammingError

from osidb.core import set_user_acls
from regulatory_reporting.models import (
    SRPReport,
    SRPReportMilestone,
    UpstreamNotification,
)
from regulatory_reporting.tests.factories import (
    SRPReportFactory,
    SRPReportMilestoneFactory,
    UpstreamNotificationFactory,
)

pytestmark = pytest.mark.enable_rls


@pytest.fixture(autouse=True)
def reset_acl():
    for db_alias in connections:
        with connections[db_alias].cursor() as cursor:
            cursor.execute("RESET osidb.acl")


class TestSRPReportRLS:
    @pytest.mark.parametrize(
        "embargoed,acls",
        [
            (False, settings.PUBLIC_READ_GROUPS + [settings.PUBLIC_WRITE_GROUP]),
            (True, [settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP]),
        ],
    )
    def test_create(self, embargoed, acls):
        with transaction.atomic():
            with pytest.raises(
                ProgrammingError, match="violates row-level security policy"
            ):
                SRPReportFactory(flaw__embargoed=embargoed)
        set_user_acls(acls)
        assert SRPReportFactory(flaw__embargoed=embargoed)

    @pytest.mark.parametrize(
        "embargoed,acls",
        [
            (False, settings.PUBLIC_READ_GROUPS + [settings.PUBLIC_WRITE_GROUP]),
            (True, [settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP]),
        ],
    )
    def test_read(self, embargoed, acls):
        assert SRPReport.objects.count() == 0
        set_user_acls(acls)
        report = SRPReportFactory(flaw__embargoed=embargoed)
        assert report

        set_user_acls(acls[:1])
        assert SRPReport.objects.count() == 1
        assert SRPReport.objects.first().pk == report.pk

    def test_read_multiple(self):
        assert SRPReport.objects.count() == 0
        set_user_acls(settings.ALL_GROUPS)
        public_pk = SRPReportFactory(flaw__embargoed=False).pk
        embargo_pk = SRPReportFactory(flaw__embargoed=True).pk
        assert SRPReport.objects.count() == 2

        set_user_acls(settings.PUBLIC_READ_GROUPS)
        assert SRPReport.objects.count() == 1
        assert SRPReport.objects.first().pk == public_pk

        set_user_acls([settings.EMBARGO_READ_GROUP])
        assert SRPReport.objects.count() == 1
        assert SRPReport.objects.first().pk == embargo_pk

    def test_update(self):
        set_user_acls(settings.ALL_GROUPS)
        r1 = SRPReportFactory(flaw__embargoed=False)
        r2 = SRPReportFactory(flaw__embargoed=True)

        set_user_acls(settings.PUBLIC_READ_GROUPS + [settings.PUBLIC_WRITE_GROUP])
        r1.title = "updated"
        r1.save(raise_validation_error=False)
        assert r1.title == "updated"

        assert SRPReport.objects.filter(pk=r2.pk).update(title="should fail") == 0

        set_user_acls([settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP])
        r2 = SRPReport.objects.get(pk=r2.pk)
        assert r2.title != "should fail"
        r2.title = "updated"
        r2.save(raise_validation_error=False)
        assert r2.title == "updated"

    def test_delete(self):
        set_user_acls(settings.ALL_GROUPS)
        r1 = SRPReportFactory(flaw__embargoed=False)
        r2 = SRPReportFactory(flaw__embargoed=True)

        set_user_acls(settings.PUBLIC_READ_GROUPS + [settings.PUBLIC_WRITE_GROUP])
        assert SRPReport.objects.count() == 1
        assert r1.delete()
        assert SRPReport.objects.count() == 0

        with transaction.atomic():
            with pytest.raises(SRPReport.DoesNotExist):
                SRPReport.objects.get(pk=r2.pk).delete()

        set_user_acls([settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP])
        assert SRPReport.objects.count() == 1
        assert SRPReport.objects.get(pk=r2.pk).delete()
        assert SRPReport.objects.count() == 0


class TestSRPReportMilestoneRLS:
    @pytest.mark.parametrize(
        "embargoed,acls",
        [
            (False, settings.PUBLIC_READ_GROUPS + [settings.PUBLIC_WRITE_GROUP]),
            (True, [settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP]),
        ],
    )
    def test_create(self, embargoed, acls):
        with transaction.atomic():
            with pytest.raises(
                ProgrammingError, match="violates row-level security policy"
            ):
                SRPReportMilestoneFactory(
                    srp_report__flaw__embargoed=embargoed,
                )
        set_user_acls(acls)
        assert SRPReportMilestoneFactory(
            srp_report__flaw__embargoed=embargoed,
        )

    @pytest.mark.parametrize(
        "embargoed,acls",
        [
            (False, settings.PUBLIC_READ_GROUPS + [settings.PUBLIC_WRITE_GROUP]),
            (True, [settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP]),
        ],
    )
    def test_read(self, embargoed, acls):
        assert SRPReportMilestone.objects.count() == 0
        set_user_acls(acls)
        milestone = SRPReportMilestoneFactory(
            srp_report__flaw__embargoed=embargoed,
        )
        assert milestone

        set_user_acls(acls[:1])
        assert SRPReportMilestone.objects.count() == 1

    def test_read_multiple(self):
        assert SRPReportMilestone.objects.count() == 0
        set_user_acls(settings.ALL_GROUPS)
        public_pk = SRPReportMilestoneFactory(
            srp_report__flaw__embargoed=False,
        ).pk
        embargo_pk = SRPReportMilestoneFactory(
            srp_report__flaw__embargoed=True,
        ).pk
        assert SRPReportMilestone.objects.count() == 2

        set_user_acls(settings.PUBLIC_READ_GROUPS)
        assert SRPReportMilestone.objects.count() == 1
        assert SRPReportMilestone.objects.first().pk == public_pk

        set_user_acls([settings.EMBARGO_READ_GROUP])
        assert SRPReportMilestone.objects.count() == 1
        assert SRPReportMilestone.objects.first().pk == embargo_pk

    def test_delete(self):
        set_user_acls(settings.ALL_GROUPS)
        m1 = SRPReportMilestoneFactory(srp_report__flaw__embargoed=False)
        m2 = SRPReportMilestoneFactory(srp_report__flaw__embargoed=True)

        set_user_acls(settings.PUBLIC_READ_GROUPS + [settings.PUBLIC_WRITE_GROUP])
        assert SRPReportMilestone.objects.count() == 1
        assert m1.delete()
        assert SRPReportMilestone.objects.count() == 0

        with transaction.atomic():
            with pytest.raises(SRPReportMilestone.DoesNotExist):
                SRPReportMilestone.objects.get(pk=m2.pk).delete()

        set_user_acls([settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP])
        assert SRPReportMilestone.objects.count() == 1
        assert SRPReportMilestone.objects.get(pk=m2.pk).delete()
        assert SRPReportMilestone.objects.count() == 0


class TestUpstreamNotificationRLS:
    @pytest.mark.parametrize(
        "embargoed,acls",
        [
            (False, settings.PUBLIC_READ_GROUPS + [settings.PUBLIC_WRITE_GROUP]),
            (True, [settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP]),
        ],
    )
    def test_create(self, embargoed, acls):
        with transaction.atomic():
            with pytest.raises(
                ProgrammingError, match="violates row-level security policy"
            ):
                UpstreamNotificationFactory(flaw__embargoed=embargoed)
        set_user_acls(acls)
        assert UpstreamNotificationFactory(flaw__embargoed=embargoed)

    @pytest.mark.parametrize(
        "embargoed,acls",
        [
            (False, settings.PUBLIC_READ_GROUPS + [settings.PUBLIC_WRITE_GROUP]),
            (True, [settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP]),
        ],
    )
    def test_read(self, embargoed, acls):
        assert UpstreamNotification.objects.count() == 0
        set_user_acls(acls)
        notification = UpstreamNotificationFactory(flaw__embargoed=embargoed)
        assert notification

        set_user_acls(acls[:1])
        assert UpstreamNotification.objects.count() == 1

    def test_read_multiple(self):
        assert UpstreamNotification.objects.count() == 0
        set_user_acls(settings.ALL_GROUPS)
        public_pk = UpstreamNotificationFactory(flaw__embargoed=False).pk
        embargo_pk = UpstreamNotificationFactory(flaw__embargoed=True).pk
        assert UpstreamNotification.objects.count() == 2

        set_user_acls(settings.PUBLIC_READ_GROUPS)
        assert UpstreamNotification.objects.count() == 1
        assert UpstreamNotification.objects.first().pk == public_pk

        set_user_acls([settings.EMBARGO_READ_GROUP])
        assert UpstreamNotification.objects.count() == 1
        assert UpstreamNotification.objects.first().pk == embargo_pk

    def test_delete(self):
        set_user_acls(settings.ALL_GROUPS)
        n1 = UpstreamNotificationFactory(flaw__embargoed=False)
        n2 = UpstreamNotificationFactory(flaw__embargoed=True)

        set_user_acls(settings.PUBLIC_READ_GROUPS + [settings.PUBLIC_WRITE_GROUP])
        assert UpstreamNotification.objects.count() == 1
        assert n1.delete()
        assert UpstreamNotification.objects.count() == 0

        with transaction.atomic():
            with pytest.raises(UpstreamNotification.DoesNotExist):
                UpstreamNotification.objects.get(pk=n2.pk).delete()

        set_user_acls([settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP])
        assert UpstreamNotification.objects.count() == 1
        assert UpstreamNotification.objects.get(pk=n2.pk).delete()
        assert UpstreamNotification.objects.count() == 0
