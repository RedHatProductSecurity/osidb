import uuid

import pytest
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from freezegun import freeze_time

from apps.taskman.service import JiraTaskmanQuerier
from apps.workflows.models import Workflow
from apps.workflows.workflow import WorkflowFramework, WorkflowModel
from collectors.bzimport.convertors import FlawConvertor
from osidb.core import generate_acls
from osidb.exceptions import DataInconsistencyException
from osidb.models import Flaw, FlawSource, Impact
from osidb.tests.factories import AffectFactory, FlawFactory, PsModuleFactory

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
            match=r"Unknown ACL group given - known are: .*",
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

    def test_set_acl_read(self):
        """
        Test that ACLMixin.set_acl_read correctly overwrites acl_read.
        """
        my_flaw = self.create_flaw(
            acl_read=["foo", "bar"], acl_write=["baz"], save=False
        )
        original_acl_read = my_flaw.acl_read
        assert len(my_flaw.acl_read) > 1
        assert original_acl_read == [self.group2acl(g) for g in ["foo", "bar"]]

        my_flaw.set_acl_read("bar")
        assert my_flaw.acl_read != original_acl_read
        assert len(my_flaw.acl_read) == 1

    def test_set_acl_write(self):
        """
        Test that ACLMixin.set_acl_write correctly overwrites acl_write.
        """
        my_flaw = self.create_flaw(
            acl_read=["foo"], acl_write=["bar", "baz"], save=False
        )
        original_acl_write = my_flaw.acl_write
        assert len(my_flaw.acl_write) > 1
        assert original_acl_write == [self.group2acl(g) for g in ["bar", "baz"]]

        my_flaw.set_acl_write("bar")
        assert my_flaw.acl_write != original_acl_write
        assert len(my_flaw.acl_write) == 1

    @pytest.mark.parametrize(
        "acl_read,acl_write,visibility",
        [
            (settings.PUBLIC_READ_GROUPS, [settings.PUBLIC_WRITE_GROUP], "public"),
            (
                [settings.EMBARGO_READ_GROUP],
                [settings.EMBARGO_WRITE_GROUP],
                "embargoed",
            ),
            (
                [settings.INTERNAL_READ_GROUP],
                [settings.INTERNAL_WRITE_GROUP],
                "internal",
            ),
        ],
    )
    def test_set_acls(self, acl_read, acl_write, visibility):
        """
        Test that ACLMixin.set_{public,embargoed,internal} works correctly.
        """
        my_flaw = self.create_flaw(acl_read=["foo"], acl_write=["bar"], save=False)
        original_acl_read = my_flaw.acl_read
        original_acl_write = my_flaw.acl_write
        assert original_acl_read == [self.group2acl("foo")]
        assert original_acl_write == [self.group2acl("bar")]

        getattr(my_flaw, f"set_{visibility}")()
        assert my_flaw.acl_read != original_acl_read
        assert my_flaw.acl_write != original_acl_write
        assert my_flaw.acl_read == [self.group2acl(g) for g in acl_read]
        assert my_flaw.acl_write == [self.group2acl(g) for g in acl_write]


class TestTrackingMixin:
    def get_acl_read(self):
        return [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]

    def get_acl_write(self):
        return [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec-write",
            )
        ]

    def create_flaw(self, **kwargs):
        """shortcut to create minimal flaw"""
        return Flaw(
            title="title",
            cwe_id="CWE-1",
            comment_zero="comment_zero",
            impact=Impact.LOW,
            components=["curl"],
            source=FlawSource.INTERNET,
            acl_read=self.get_acl_read(),
            acl_write=self.get_acl_write(),
            reported_dt=timezone.now(),
            unembargo_dt=tzdatetime(2000, 1, 1),
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
            "component": "vulnerability",
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
            task_bug=None,
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

    @freeze_time(tzdatetime(2023, 10, 11))
    def test_tracking_mixin_manager_auto_timestamps(self):
        """
        test that the auto_timestamps are handled as expected in TrackingMixinManager
        """
        # minimal valid Flaw data
        kwargs = dict(
            title="title",
            cwe_id="CWE-1",
            comment_zero="comment_zero",
            impact=Impact.LOW,
            components=["curl"],
            source=FlawSource.INTERNET,
            acl_read=self.get_acl_read(),
            acl_write=self.get_acl_write(),
            created_dt=tzdatetime(2000, 1, 1),  # different from now
            updated_dt=tzdatetime(2000, 1, 1),  # different from now
            reported_dt=tzdatetime(2000, 1, 1),
            unembargo_dt=tzdatetime(2000, 1, 1),
        )

        # timestamps should be auto rewritten to now
        flaw = Flaw.objects.create(auto_timestamps=True, **kwargs)
        assert flaw.created_dt == timezone.now()
        assert flaw.updated_dt == timezone.now()

        # timestamps should be preserved as provided
        flaw = Flaw.objects.create(auto_timestamps=False, **kwargs)
        assert flaw.created_dt == tzdatetime(2000, 1, 1)
        assert flaw.updated_dt == tzdatetime(2000, 1, 1)

        # the default behavior
        # timestamps should be auto rewritten to now
        flaw = Flaw.objects.create(**kwargs)
        assert flaw.created_dt == timezone.now()
        assert flaw.updated_dt == timezone.now()


class TestBugzillaJiraMixinInteration:
    def get_acl_read(self):
        return [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]

    def get_acl_write(self):
        return [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec-write",
            )
        ]

    def enable_sync(self, monkeypatch):
        """Enables all sync to test integration between mixins"""
        import apps.bbsync.mixins as bz_mixins
        import apps.taskman.mixins as task_mixins
        import osidb.models as models
        import osidb.serializer as serializer

        monkeypatch.setattr(task_mixins, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
        monkeypatch.setattr(models, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
        monkeypatch.setattr(serializer, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
        monkeypatch.setattr(bz_mixins, "SYNC_TO_BZ", True)
        monkeypatch.setattr(models, "SYNC_FLAWS_TO_BZ", True)
        monkeypatch.setattr(models, "SYNC_TRACKERS_TO_BZ", True)
        monkeypatch.setattr(models, "SYNC_TO_JIRA", True)

        monkeypatch.setenv("HTTPS_PROXY", "http://squid.corp.redhat.com:3128")

    def setup_workflow(self):
        """Clean default workflows and set a basic workflow for testing"""

        state_new = {
            "name": WorkflowModel.WorkflowState.NEW,
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }
        state_second = {
            "name": WorkflowModel.WorkflowState.TRIAGE,
            "requirements": ["has title"],
            "jira_state": "Refinement",
            "jira_resolution": None,
        }

        workflow_main = Workflow(
            {
                "name": "DEFAULT",
                "description": "a two step workflow",
                "priority": 0,
                "conditions": [],
                "states": [state_new, state_second],
            }
        )

        state_reject = {
            "name": WorkflowModel.WorkflowState.REJECTED,
            "requirements": [],
            "jira_state": "Closed",
            "jira_resolution": "Won't Do",
        }
        workflow_reject = Workflow(
            {
                "name": "REJECTED",
                "description": "a two step workflow",
                "priority": 0,
                "conditions": [],
                "states": [state_reject],
            }
        )
        workflow_framework = WorkflowFramework()
        # remove yml workflows
        workflow_framework._workflows = []
        workflow_framework.register_workflow(workflow_main)
        workflow_framework.register_workflow(workflow_reject)

    @pytest.mark.vcr
    def test_manual_changes(self, monkeypatch):
        """Test that sync occurs using internal OSIDB APIs"""
        self.enable_sync(monkeypatch)
        self.setup_workflow()
        flaw = Flaw(
            title="title",
            cwe_id="CWE-1",
            comment_zero="comment_zero",
            impact=Impact.LOW,
            components=["curl"],
            source=FlawSource.INTERNET,
            acl_read=self.get_acl_read(),
            acl_write=self.get_acl_write(),
            reported_dt=timezone.now(),
            unembargo_dt=tzdatetime(2000, 1, 1),
        )

        jira_token = "SECRET"
        bz_token = "SECRET"

        flaw.save(jira_token=jira_token, bz_api_key=bz_token)

        PsModuleFactory(name="ps-module-0")
        assert flaw.bz_id
        assert flaw.task_key
        assert flaw.meta_attr["bz_component"] == "vulnerability-draft"

        AffectFactory(flaw=flaw, ps_module="ps-module-0")
        flaw = Flaw.objects.get(pk=flaw.uuid)

        flaw.promote(jira_token=jira_token, bz_api_key=bz_token)
        assert flaw.workflow_state == WorkflowModel.WorkflowState.TRIAGE
        assert flaw.meta_attr["bz_component"] == "vulnerability"

        jtq = JiraTaskmanQuerier(jira_token)

        issue = jtq.jira_conn.issue(flaw.task_key).raw
        assert issue["fields"]["status"]["name"] == "Refinement"
        flaw.reject(jira_token=jira_token, bz_api_key=bz_token)
        assert flaw.workflow_state == WorkflowModel.WorkflowState.REJECTED

        issue = jtq.jira_conn.issue(flaw.task_key).raw
        assert issue["fields"]["status"]["name"] == "Closed"
        assert issue["fields"]["resolution"]["name"] == "Won't Do"

    @pytest.mark.vcr
    @pytest.mark.enable_signals
    def test_api_changes(self, monkeypatch, auth_client, test_api_uri):
        """Test that sync occurs using OSIDB REST API"""
        self.enable_sync(monkeypatch)
        self.setup_workflow()

        jira_token = "SECRET"
        bz_token = "SECRET"

        flaw_data = {
            "title": "Foo",
            "comment_zero": "test",
            "impact": "LOW",
            "components": ["curl"],
            "source": "DEBIAN",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "mitigation": "mitigation",
            "embargoed": "false",
        }
        response = auth_client().post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bz_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]
        flaw = Flaw.objects.get(pk=created_uuid)

        PsModuleFactory(name="ps-module-0")
        assert flaw.bz_id
        assert flaw.task_key
        assert flaw.meta_attr["bz_component"] == "vulnerability-draft"

        AffectFactory(flaw=flaw, ps_module="ps-module-0")

        response = auth_client().post(
            f"{test_api_uri}/flaws/{created_uuid}/promote",
            format="json",
            HTTP_BUGZILLA_API_KEY=bz_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        flaw = Flaw.objects.get(pk=created_uuid)
        assert flaw.workflow_state == WorkflowModel.WorkflowState.TRIAGE
        assert flaw.meta_attr["bz_component"] == "vulnerability"

        jtq = JiraTaskmanQuerier(jira_token)

        issue = jtq.jira_conn.issue(flaw.task_key).raw
        assert issue["fields"]["status"]["name"] == "Refinement"

        response = auth_client().post(
            f"{test_api_uri}/flaws/{created_uuid}/reject",
            {"reason": "This is not a bug."},
            format="json",
            HTTP_BUGZILLA_API_KEY=bz_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        issue = jtq.jira_conn.issue(flaw.task_key).raw
        assert issue["fields"]["status"]["name"] == "Closed"
        assert issue["fields"]["resolution"]["name"] == "Won't Do"
