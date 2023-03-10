import pytest
from django.utils import timezone
from freezegun import freeze_time

from osidb.models import Flaw

from .factories import FlawFactory

pytestmark = pytest.mark.unit


class TestEmbargo(object):
    def test_factory(
        self,
        public_read_groups,
        public_write_groups,
        embargoed_read_groups,
        embargoed_write_groups,
    ):
        flaw = FlawFactory(embargoed=False)
        assert flaw.acl_read == public_read_groups
        assert flaw.acl_write == public_write_groups

        flaw = FlawFactory(embargoed=True)
        assert flaw.acl_read == embargoed_read_groups
        assert flaw.acl_write == embargoed_write_groups

    @pytest.mark.parametrize("embargoed", [False, True])
    @freeze_time(timezone.datetime(2022, 11, 25))
    def test_embargoed_annotation(
        self,
        public_read_groups,
        public_write_groups,
        embargoed_read_groups,
        embargoed_write_groups,
        embargoed,
    ):
        if embargoed:
            read_groups = embargoed_read_groups
            write_groups = embargoed_write_groups
            title = "EMBARGOED CVE-2022-1234 kernel: some description"
            source = "REDHAT"
            unembargo_dt = timezone.datetime(
                2022, 12, 26, tzinfo=timezone.get_current_timezone()
            )
        else:
            read_groups = public_read_groups
            write_groups = public_write_groups
            title = "CVE-2022-1234 kernel: some description"
            source = "INTERNET"
            unembargo_dt = timezone.datetime(
                2022, 11, 24, tzinfo=timezone.get_current_timezone()
            )
        flaw = Flaw(
            acl_read=read_groups,
            acl_write=write_groups,
            cve_id="CVE-2000-11111",
            cwe_id="CWE-1",
            type="VULNERABILITY",
            state="NEW",
            resolution="",
            impact="LOW",
            source=source,
            title=title,
            description="test",
            reported_dt=timezone.now(),
            unembargo_dt=unembargo_dt,
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
        )
        flaw.save()
        flaw = Flaw.objects.get(cve_id="CVE-2000-11111")
        assert flaw.embargoed == embargoed

    @pytest.mark.parametrize("embargoed", [False, True])
    def test_embargoed_readonly(
        self, public_read_groups, public_write_groups, embargoed
    ):
        with pytest.raises(TypeError) as ex:
            flaw = Flaw(
                acl_read=public_read_groups,
                acl_write=public_write_groups,
                cve_id="CVE-2000-11111",
                type="VULNERABILITY",
                state="NEW",
                resolution="",
                impact="LOW",
                title="test",
                description="test",
                embargoed=embargoed,
                reported_dt=timezone.now(),
                cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            )
            flaw.save()
        assert "Flaw() got an unexpected keyword argument 'embargoed'" in str(ex)
