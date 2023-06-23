import uuid

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone
from freezegun import freeze_time

from collectors.bzimport.convertors import FlawConvertor
from osidb.core import generate_acls
from osidb.exceptions import DataInconsistencyException
from osidb.models import Flaw, FlawSource, Impact
from osidb.tests.factories import AffectFactory, FlawFactory

from .test_flaw import tzdatetime

pytestmark = pytest.mark.unit


class TestACLMixin:
    """
    negative tests of ACL validations
    the positive tests are all over the test suite
    """

    def group2acl(self, group):
        """
        translate the human-readable LDAP group
        name to the corresponding UUID ACL hash
        """
        return uuid.UUID(generate_acls([group])[0])

    def create_flaw(self, acl_read=None, acl_write=None, save=True):
        """
        shortcut for creating a flaw with the given ACLs
        """
        kwargs = {}
        if acl_read is not None:
            kwargs["acl_read"] = [self.group2acl(group) for group in acl_read]
        if acl_write is not None:
            kwargs["acl_write"] = [self.group2acl(group) for group in acl_write]
        return FlawFactory(**kwargs) if save else FlawFactory.build(**kwargs)

    def test_empty_acl_read(self):
        """
        test that an empty read ACL is not allowed
        """
        with pytest.raises(
            ValidationError, match="acl_read.....This field cannot be blank"
        ):
            FlawFactory(acl_read=[])

    def test_empty_acl_write(self):
        """
        test that an empty write ACL is not allowed
        """
        with pytest.raises(
            ValidationError, match="acl_write.....This field cannot be blank"
        ):
            FlawFactory(acl_write=[])

    @pytest.mark.parametrize(
        "acl_read,acl_write",
        [
            (["data-prodsec", "unknown-group"], ["data-prodsec-write"]),
            (["date-topsecret"], ["data-topsecret-write", "unknown-group"]),
            (
                ["date-topsecret", "unknown-group"],
                ["data-topsecret-write", "unknown-group"],
            ),
        ],
    )
    def test_known_acls(self, acl_read, acl_write):
        """
        test that both ACLs contains identical LDAP groups
        of course with respect to read|write difference
        """
        with pytest.raises(
            ValidationError,
            match=(
                "Unknown ACL group given - known are: data-prodsec, "
                "data-prodsec-write, data-topsecret, data-topsecret-write"
            ),
        ):
            flaw = self.create_flaw(acl_read=acl_read, acl_write=acl_write, save=False)
            flaw._validate_acls_known()

    @pytest.mark.parametrize(
        "acl_read",
        [
            (["data-prodsec-write"]),
            (["data-prodsec-write", "data-topsecret-write"]),
            (["data-prodsec", "data-prodsec-write"]),
            (["data-topsecret", "data-topsecret-write"]),
        ],
    )
    def test_meaningful_acl_read(self, acl_read):
        """
        test that read ACL contains only read LDAP groups
        """
        with pytest.raises(
            ValidationError, match="Read ACL contains non-read ACL group:"
        ):
            flaw = self.create_flaw(acl_read=acl_read, save=False)
            flaw._validate_acl_read_meaningful()

    @pytest.mark.parametrize(
        "acl_write",
        [
            (["data-prodsec"]),
            (["data-prodsec", "data-topsecret"]),
            (["data-prodsec", "data-prodsec-write"]),
            (["data-topsecret", "data-topsecret-write"]),
        ],
    )
    def test_meaningful_acl_write(self, acl_write):
        """
        test that write ACL contains only read LDAP groups
        """
        with pytest.raises(
            ValidationError, match="Write ACL contains non-write ACL group:"
        ):
            flaw = self.create_flaw(acl_write=acl_write, save=False)
            flaw._validate_acl_write_meaningful()

    @pytest.mark.parametrize(
        "acl_write",
        [
            (["data-prodsec-write"]),
            (["data-prodsec-write", "data-topsecret-write"]),
        ],
    )
    def test_unexpected_embargoed_acl(self, acl_write):
        """
        test that embargoed ACL contains only expected LDAP groups
        which means the embaroed LDAP groups only
        """
        with pytest.raises(
            ValidationError, match="Unexpected ACL group in embargoed ACLs:"
        ):
            # the read ACL is given as it defines the embargo
            self.create_flaw(acl_read=["data-topsecret"], acl_write=acl_write)

    @pytest.mark.parametrize(
        "acl_read,acl_write",
        [
            (["data-prodsec", "data-topsecret"], ["data-prodsec-write"]),
            (["data-prodsec"], ["data-prodsec-write", "data-topsecret-write"]),
        ],
    )
    def test_unexpected_non_embargoed_acl(self, acl_read, acl_write):
        """
        test that non-embargoed ACL contains only expected LDAP groups
        which means the public LDAP groups only
        """
        with pytest.raises(
            ValidationError, match="Unexpected ACL group in non-embargoed ACLs:"
        ):
            self.create_flaw(acl_read=acl_read, acl_write=acl_write)

    @pytest.mark.parametrize(
        "acl_read,acl_write",
        [
            (["data-prodsec", "data-prodsec"], ["data-prodsec-write"]),
            (["data-topsecret"], ["data-topsecret-write", "data-topsecret-write"]),
        ],
    )
    def test_duplicite_acl(self, acl_read, acl_write):
        """
        test that non-embargoed ACL contains only expected LDAP groups
        which means the public LDAP groups only
        """
        with pytest.raises(
            ValidationError, match="ACLs must not contain duplicit ACL groups"
        ):
            self.create_flaw(acl_read=acl_read, acl_write=acl_write)


class TestTrackingMixin:
    def create_flaw(self, **kwargs):
        """shortcut to create minimal flaw"""
        acl_read = [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]
        acl_write = [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec-write",
            )
        ]
        return Flaw(
            title="title",
            cwe_id="CWE-1",
            description="description",
            impact=Impact.LOW,
            component="curl",
            source=FlawSource.INTERNET,
            acl_read=acl_read,
            acl_write=acl_write,
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
            "status": "NEW",
            "resolution": "",
        }

    def get_flaw_bug_convertor(self):
        """shortcut to create minimal flaw bug convertor"""
        return FlawConvertor(
            flaw_bug=self.get_flaw_bug(),
            flaw_comments=[],
            flaw_history={"bugs": [{"history": []}]},
            task_bug=None,
            tracker_bugs=[],
            tracker_jiras=[],
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
        meta_attr = {"bz_id": "12345"}
        flaw = self.create_flaw(cve_id="CVE-2020-12345", meta_attr=meta_attr)
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
