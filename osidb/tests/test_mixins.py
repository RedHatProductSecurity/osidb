import uuid

import pytest
from django.utils import timezone
from freezegun import freeze_time

from collectors.bzimport.convertors import FlawBugConvertor
from osidb.exceptions import DataInconsistencyException
from osidb.models import Flaw
from osidb.tests.factories import AffectFactory, FlawFactory

from .test_flaw import tzdatetime

pytestmark = pytest.mark.unit


class TestTrackingMixin:
    def create_flaw(self, **kwargs):
        """shortcut to create minimal flaw"""
        acls = [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]
        return Flaw(
            title="title",
            cwe_id="CWE-1",
            description="description",
            acl_read=acls,
            acl_write=acls,
            reported_dt=timezone.now(),
            unembargo_dt=tzdatetime(2000, 1, 1),
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            **kwargs,
        )

    @freeze_time(tzdatetime(2022, 12, 24))
    def test_create_implicit(self):
        """
        test creation of default timestamps so
        when not specified they are auto-set to now
        """
        flaw = self.create_flaw()

        assert flaw.created_dt is None
        assert flaw.updated_dt is None

        flaw.save()

        assert flaw.created_dt == tzdatetime(2022, 12, 24)
        assert flaw.updated_dt == tzdatetime(2022, 12, 24)

    @freeze_time(tzdatetime(2022, 12, 24))
    def test_create_explicit(self):
        """
        test creation of specified timestamps so
        when specified they are not auto-set
        """
        flaw = self.create_flaw(
            created_dt=tzdatetime(2020, 12, 24),
            updated_dt=tzdatetime(2021, 12, 24),
        )

        assert flaw.created_dt == tzdatetime(2020, 12, 24)
        assert flaw.updated_dt == tzdatetime(2021, 12, 24)

        flaw.save(auto_timestamps=False)

        assert flaw.created_dt == tzdatetime(2020, 12, 24)
        assert flaw.updated_dt == tzdatetime(2021, 12, 24)

    @freeze_time(tzdatetime(2022, 12, 24))
    def test_change_implicit(self):
        """
        test implicit changes of timestamps in time so
        when not specified created_dt does not automatically
        change while updated_dt changes on every save
        """
        flaw = self.create_flaw()
        flaw.save()
        AffectFactory(flaw=flaw)

        assert flaw.created_dt == tzdatetime(2022, 12, 24)
        assert flaw.updated_dt == tzdatetime(2022, 12, 24)

        with freeze_time(tzdatetime(2023, 12, 24)):
            flaw.save()

            assert flaw.created_dt == tzdatetime(2022, 12, 24)
            assert flaw.updated_dt == tzdatetime(2023, 12, 24)

    @freeze_time(tzdatetime(2022, 12, 24))
    def test_change_explicit(self):
        """
        test explicit changes of timestamps in time so
        when specified they changes to the given values
        """
        flaw = self.create_flaw()
        flaw.save()
        AffectFactory(flaw=flaw)

        assert flaw.created_dt == tzdatetime(2022, 12, 24)
        assert flaw.updated_dt == tzdatetime(2022, 12, 24)

        with freeze_time(tzdatetime(2023, 12, 24)):
            flaw.created_dt = tzdatetime(2021, 12, 24)
            flaw.save()

            # no explicit created_dt change without auto_timestamps=False
            assert flaw.created_dt == tzdatetime(2022, 12, 24)

            flaw.updated_dt = tzdatetime(2021, 12, 24)
            with pytest.raises(DataInconsistencyException):
                # explicit updated_dt change without auto_timestamps=False
                # is a mid-air collision from the model point of view
                flaw.save()

        with freeze_time(tzdatetime(2023, 12, 24)):
            flaw.created_dt = tzdatetime(2021, 12, 24)
            flaw.updated_dt = tzdatetime(2021, 12, 24)
            flaw.save(auto_timestamps=False)

            assert flaw.created_dt == tzdatetime(2021, 12, 24)
            assert flaw.updated_dt == tzdatetime(2021, 12, 24)

    @freeze_time(tzdatetime(2022, 12, 24))
    def test_conflicting(self):
        """
        test conflicting model changes
        saving an outdated model instance should fail
        """
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        flaw_copy = Flaw.objects.first()

        with freeze_time(tzdatetime(2023, 12, 24)):
            flaw.save()

        with freeze_time(tzdatetime(2024, 12, 24)):
            with pytest.raises(DataInconsistencyException):
                flaw_copy.save()

    def get_flaw_bug(self):
        """shortcut to create minimal flaw bug"""
        return {
            "id": 12345,
            "alias": ["CVE-2020-12345"],
            "summary": "summary",
            "description": "description",
            "fixed_in": None,
            "depends_on": [],
            "creation_time": tzdatetime(2020, 12, 24),
            "last_change_time": tzdatetime(2021, 12, 24),
            "cf_srtnotes": "",
        }

    def get_flaw_bug_convertor(self):
        """shortcut to create minimal flaw bug convertor"""
        return FlawBugConvertor(
            flaw_bug=self.get_flaw_bug(),
            flaw_comments=[],
            flaw_history={"bugs": [{"history": []}]},
            task_bug=None,
            tracker_bugs=[],
            tracker_jiras=[],
            nvd_cvss={},
        )

    @freeze_time(tzdatetime(2022, 12, 24))
    def test_import_new(self):
        """
        test Bugzilla flaw bug convertion and save when importing a new flaw
        """
        convertor = self.get_flaw_bug_convertor()
        pre_flaw = convertor.flaws[0]
        pre_flaw.save()
        # assume a flaw can be loaded multiple times by collector
        # and it should always respect the collected timestamps
        # - resync or some collector debugging ...
        pre_flaw.save()

        flaw = Flaw.objects.get(cve_id="CVE-2020-12345")
        assert flaw.created_dt == tzdatetime(2020, 12, 24)
        assert flaw.updated_dt == tzdatetime(2021, 12, 24)

    @freeze_time(tzdatetime(2022, 12, 24))
    def test_import_existing(self):
        """
        test Bugzilla flaw bug convertion and save when importing an existing flaw
        """
        flaw = self.create_flaw(cve_id="CVE-2020-12345")
        flaw.save()

        convertor = self.get_flaw_bug_convertor()
        pre_flaw = convertor.flaws[0]
        pre_flaw.save()
        # assume a flaw can be loaded multiple times by collector
        # and it should always respect the collected timestamps
        # - resync or some collector debugging ...
        pre_flaw.save()

        flaw = Flaw.objects.get(cve_id="CVE-2020-12345")
        assert flaw.created_dt == tzdatetime(2020, 12, 24)
        assert flaw.updated_dt == tzdatetime(2021, 12, 24)
