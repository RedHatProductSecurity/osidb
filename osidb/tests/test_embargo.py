import pytest
from django.utils import timezone

from osidb.models import Flaw

from .factories import FlawFactory

pytestmark = pytest.mark.unit


class TestEmbargo(object):
    def test_factory(self, public_groups, embargoed_groups):
        flaw = FlawFactory(embargoed=False)
        assert flaw.acl_read == public_groups

        flaw = FlawFactory(embargoed=True)
        assert flaw.acl_read == embargoed_groups

    @pytest.mark.parametrize("embargoed", [False, True])
    def test_embargoed_annotation(self, embargoed_groups, public_groups, embargoed):
        groups = embargoed_groups if embargoed else public_groups
        flaw = Flaw(
            acl_read=groups,
            acl_write=groups,
            cve_id="CVE-2000-11111",
            type="VULNERABILITY",
            state="NEW",
            resolution="",
            impact="LOW",
            title="test",
            description="test",
            reported_dt=timezone.now(),
            unembargo_dt=timezone.now(),
        )
        flaw.save()
        flaw = Flaw.objects.get(cve_id="CVE-2000-11111")
        assert flaw.embargoed == embargoed

    @pytest.mark.parametrize("embargoed", [False, True])
    def test_embargoed_readonly(self, public_groups, embargoed_groups, embargoed):
        with pytest.raises(TypeError) as ex:
            flaw = Flaw(
                acl_read=public_groups,
                acl_write=public_groups,
                cve_id="CVE-2000-11111",
                type="VULNERABILITY",
                state="NEW",
                resolution="",
                impact="LOW",
                title="test",
                description="test",
                embargoed=embargoed,
                reported_dt=timezone.now(),
            )
            flaw.save()
        assert "Flaw() got an unexpected keyword argument 'embargoed'" in str(ex)

    # TODO the following is not applicable any more
    # but should be resurrected once we start implement write functionality
    #
    # def test_setting_embargo(self):
    #     """explicitly test setting of embargo"""
    #     flaw = FlawFactory()

    #     # | embargoed | unembargo_dt | embargoed set value |
    #     # |-----------|--------------|---------------------|
    #     # | True      | None         | True                |
    #     flaw.embargoed = True
    #     flaw.unembargo_dt = None
    #     assert flaw.process_embargo_state() is None
    #     assert flaw.embargoed is True

    #     # | False      | None        | False               |
    #     flaw.embargoed = False
    #     flaw.unembargo_dt = None
    #     assert flaw.process_embargo_state() is None
    #     assert flaw.embargoed is False

    #     # | None      | None         | False               |
    #     flaw.embargoed = None
    #     flaw.unembargo_dt = None
    #     assert flaw.process_embargo_state() is None
    #     assert flaw.embargoed is False

    #     # | True      | Future date  | True                |
    #     flaw.embargoed = True
    #     flaw.unembargo_dt = datetime.now() + timedelta(days=1)
    #     assert flaw.process_embargo_state() is None
    #     assert flaw.embargoed is True

    #     # | False     | Future date  | True                 |
    #     flaw.embargoed = False
    #     flaw.unembargo_dt = datetime.now() + timedelta(days=1)
    #     assert flaw.process_embargo_state() is None
    #     assert flaw.embargoed is True

    #     # | None      | Future date  | True                 |
    #     flaw.embargoed = None
    #     flaw.unembargo_dt = datetime.now() + timedelta(days=1)
    #     assert flaw.process_embargo_state() is None
    #     assert flaw.embargoed is True

    #     # | True      | Past date    | True                |
    #     flaw.embargoed = True
    #     flaw.unembargo_dt = datetime.now() - timedelta(days=1)
    #     assert flaw.process_embargo_state() is None
    #     assert flaw.embargoed is True

    #     # | False     | Past date    | False                |
    #     flaw.embargoed = False
    #     flaw.unembargo_dt = datetime.now() - timedelta(days=1)
    #     assert flaw.process_embargo_state() is None
    #     assert flaw.embargoed is False

    #     # | None      | Past date    | False                |
    #     flaw.embargoed = None
    #     flaw.unembargo_dt = datetime.now() - timedelta(days=1)
    #     assert flaw.process_embargo_state() is None
    #     assert flaw.embargoed is False
