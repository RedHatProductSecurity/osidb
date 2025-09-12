import uuid

import pytest
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.utils import timezone
from freezegun import freeze_time

from apps.taskman.service import JiraTaskmanQuerier
from apps.trackers.models import JiraBugIssuetype
from apps.trackers.tests.factories import JiraProjectFieldsFactory
from apps.workflows.models import Workflow
from apps.workflows.workflow import WorkflowFramework, WorkflowModel
from osidb.core import generate_acls
from osidb.exceptions import DataInconsistencyException
from osidb.mixins import Alert, AlertMixin
from osidb.models import (
    Affect,
    Flaw,
    FlawSource,
    Impact,
    PsModule,
    PsUpdateStream,
    Tracker,
)
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
)

from .test_flaw import tzdatetime

pytestmark = pytest.mark.unit


def get_acl_read():
    return [
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
        )
    ]


def get_acl_write():
    return [
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            "https://osidb.prod.redhat.com/ns/acls#data-prodsec-write",
        )
    ]


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
    def create_flaw(self, **kwargs):
        """shortcut to create minimal flaw"""
        return Flaw(
            title="title",
            cwe_id="CWE-1",
            comment_zero="comment_zero",
            impact=Impact.LOW,
            components=["curl"],
            source=FlawSource.INTERNET,
            acl_read=get_acl_read(),
            acl_write=get_acl_write(),
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
            acl_read=get_acl_read(),
            acl_write=get_acl_write(),
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


class TestBugzillaJiraMixinIntegration:
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
    def test_manual_changes(
        self,
        bugzilla_token,
        enable_bz_async_sync,
        enable_jira_task_sync,
        enable_jira_tracker_sync,
        jira_token,
    ):
        """Test that sync occurs using internal OSIDB APIs"""
        self.setup_workflow()
        flaw = Flaw(
            title="title",
            cwe_id="CWE-1",
            comment_zero="comment_zero",
            impact=Impact.LOW,
            components=["curl"],
            source=FlawSource.INTERNET,
            acl_read=get_acl_read(),
            acl_write=get_acl_write(),
            reported_dt=timezone.now(),
            unembargo_dt=tzdatetime(2000, 1, 1),
        )

        flaw.save(
            jira_token=jira_token,
            bz_api_key=bugzilla_token,
            force_synchronous_sync=True,
        )

        ps_module = PsModuleFactory(name="ps-module-0")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        assert flaw.bz_id
        assert flaw.task_key
        assert flaw.workflow_state == WorkflowModel.WorkflowState.NEW

        AffectFactory(flaw=flaw, ps_update_stream=ps_update_stream.name)
        flaw = Flaw.objects.get(uuid=flaw.uuid)

        flaw.promote(jira_token=jira_token, bz_api_key=bugzilla_token)
        flaw.refresh_from_db()  # need to refresh after update
        assert flaw.workflow_state == WorkflowModel.WorkflowState.TRIAGE

        jtq = JiraTaskmanQuerier(jira_token)

        issue = jtq.jira_conn.issue(flaw.task_key).raw
        assert issue["fields"]["status"]["name"] == "Refinement"
        flaw.reject(jira_token=jira_token, bz_api_key=bugzilla_token)
        assert flaw.workflow_state == WorkflowModel.WorkflowState.REJECTED

        issue = jtq.jira_conn.issue(flaw.task_key).raw
        assert issue["fields"]["status"]["name"] == "Closed"
        assert issue["fields"]["resolution"]["name"] == "Won't Do"

    @pytest.mark.vcr
    @pytest.mark.enable_signals
    def test_api_changes(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_async_sync,
        enable_jira_task_sync,
        enable_jira_tracker_sync,
        jira_token,
        test_api_uri,
    ):
        """Test that sync occurs using OSIDB REST API"""
        self.setup_workflow()

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
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]
        flaw = Flaw.objects.get(pk=created_uuid)

        ps_module = PsModuleFactory(name="ps-module-0")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        assert flaw.task_key
        assert flaw.workflow_state == WorkflowModel.WorkflowState.NEW

        AffectFactory(flaw=flaw, ps_update_stream=ps_update_stream.name)

        response = auth_client().post(
            f"{test_api_uri}/flaws/{created_uuid}/promote",
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        flaw = Flaw.objects.get(pk=created_uuid)
        assert flaw.workflow_state == WorkflowModel.WorkflowState.TRIAGE

        jtq = JiraTaskmanQuerier(jira_token)

        issue = jtq.jira_conn.issue(flaw.task_key).raw
        assert issue["fields"]["status"]["name"] == "Refinement"

        response = auth_client().post(
            f"{test_api_uri}/flaws/{created_uuid}/reject",
            {"reason": "This is not a bug."},
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        issue = jtq.jira_conn.issue(flaw.task_key).raw
        assert issue["fields"]["status"]["name"] == "Closed"
        assert issue["fields"]["resolution"]["name"] == "Won't Do"


class TestAlertMixin:
    @freeze_time(tzdatetime(2024, 12, 10, 12, 0, 0))
    def test_validate_dt(self):
        """Tests that last_validated_dt matches the created_dt field"""
        flaw = FlawFactory(embargoed=False, source=FlawSource.REDHAT)

        alerts = Alert.objects.filter(object_id=flaw.uuid, name="private_source_no_ack")

        assert flaw.last_validated_dt == tzdatetime(2024, 12, 10, 12, 0, 0)
        assert alerts.count() == 1
        assert alerts[0].created_dt == tzdatetime(2024, 12, 10, 12, 0, 0)

        with freeze_time(tzdatetime(2024, 12, 10, 12, 0, 1)):
            flaw.source = FlawSource.INTERNET
            flaw.save()
            alerts = Alert.objects.filter(
                object_id=flaw.uuid, name="private_source_no_ack"
            )

            assert flaw.last_validated_dt == tzdatetime(2024, 12, 10, 12, 0, 1)
            assert alerts.count() == 1
            # The alert should not be updated as is resolved
            assert alerts[0].created_dt == tzdatetime(2024, 12, 10, 12, 0, 0)


class TestMultiMixinIntegration:
    @pytest.mark.vcr
    def test_tracker_validation(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_async_sync,
        enable_jira_task_sync,
        enable_jira_tracker_sync,
        jira_token,
        test_api_uri,
    ):
        """Tests that validations will block for Trackers with all sync enabled"""
        flaw = FlawFactory(embargoed=False)
        ps_module = PsModule(
            name="rhel-8",
            bts_name="jboss",
            bts_key="RHEL",
            component_overrides="",
            default_component="kernel",
            public_description="RHEL",
            ps_product=PsProductFactory(),
            bts_groups={"public": [], "embargoed": []},
        )
        ps_module.save()

        stream = PsUpdateStream(
            name="rhel-8",
            ps_module=ps_module,
            default_to_ps_module=ps_module,
            active_to_ps_module=ps_module,
            version="40",
        )
        stream.save()

        JiraProjectFieldsFactory(
            project_key=ps_module.bts_key,
            field_id="priority",
            field_name="Priority",
            allowed_values=[
                "Blocker",
                "Critical",
                "Major",
                "Normal",
                "Minor",
                "Undefined",
            ],
        )
        JiraProjectFieldsFactory(
            project_key=ps_module.bts_key,
            field_id="security",
            field_name="Security Level",
            allowed_values=[
                "Embargoed Security Issue",
                "Red Hat Employee",
                "Red Hat Engineering Authorized",
                "Red Hat Partner",
                "Restricted",
                "Team",
            ],
        )

        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=stream.name,
            ps_component="kernel",
            affectedness="NEW",
            resolution=Affect.AffectResolution.DEFER,
        )

        tracker_data = {
            "affects": [affect.uuid],
            "embargoed": False,
            "ps_update_stream": stream.name,
            "type": "JIRA",
        }
        assert Tracker.objects.all().count() == 0

        response = auth_client().post(
            f"{test_api_uri}/trackers",
            tracker_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert any(
            "The tracker is associated with a DEFER affect" in error
            for error in response.json()["non_field_errors"]
        )
        assert response.status_code == 400
        assert affect.tracker is None
        assert Tracker.objects.all().count() == 0

    @pytest.mark.vcr
    def test_tracker_validation_bugzilla(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_async_sync,
        enable_jira_task_sync,
        enable_jira_tracker_sync,
        jira_token,
        monkeypatch,
        test_api_uri,
    ):
        """Test that bugzilla Tracker endpoint only recreates alerts when needed"""
        validation_counter = {}
        original_validate = AlertMixin.validate

        def counter_validate(self, raise_validation_error=True, dry_run=False):
            nonlocal validation_counter
            if not dry_run:
                model = str(ContentType.objects.get_for_model(self))
                if model not in validation_counter:
                    validation_counter[model] = 0
                validation_counter[model] += 1
            # preserve original method behavior for proper testing
            original_validate(self, raise_validation_error=raise_validation_error)

        ps_module = PsModule(
            name="fedora-all",
            bts_name="bugzilla",
            bts_key="Fedora",
            component_overrides="",
            default_component="kernel",
            public_description="Fedora",
            ps_product=PsProductFactory(),
            bts_groups={"public": [], "embargoed": []},
        )
        ps_module.save()
        ps_update_stream = PsUpdateStream(
            name="fedora-all",
            ps_module=ps_module,
            default_to_ps_module=ps_module,
            active_to_ps_module=ps_module,
            version="40",
        )
        ps_update_stream.save()

        flaw_data = {
            "title": "test validations",
            "comment_zero": "this is a simple test",
            "impact": "MODERATE",
            "components": ["curl"],
            "source": "REDHAT",
            "reported_dt": "2024-08-06T00:00:00.000Z",
            "unembargo_dt": "2024-08-06T00:00:00.000Z",
            "embargoed": False,
        }

        response = auth_client().post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 201
        body = response.json()
        flaw = Flaw.objects.get(uuid=body["uuid"])

        affects_data = [
            {
                "flaw": str(flaw.uuid),
                "affectedness": "AFFECTED",
                "resolution": "DELEGATED",
                "ps_update_stream": ps_update_stream.name,
                "ps_component": "kernel",
                "impact": "MODERATE",
                "embargoed": False,
            }
        ]
        response = auth_client().post(
            f"{test_api_uri}/affects/bulk",
            affects_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200
        body = response.json()
        affect = Affect.objects.get(uuid=body["results"][0]["uuid"])

        tracker_data = {
            "affects": [affect.uuid],
            "embargoed": False,
            "ps_update_stream": ps_update_stream.name,
        }
        monkeypatch.setattr(AlertMixin, "validate", counter_validate)
        response = auth_client().post(
            f"{test_api_uri}/trackers",
            tracker_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 201
        assert len(validation_counter) == 1
        assert "osidb | Flaw" not in validation_counter
        assert validation_counter["osidb | Tracker"] == 1

    @pytest.mark.vcr
    def test_tracker_validation_jira(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_async_sync,
        enable_jira_task_sync,
        enable_jira_tracker_sync,
        jira_token,
        monkeypatch,
        test_api_uri,
    ):
        """Test that jira Tracker endpoint only recreates alerts when needed"""
        validation_counter = {}
        original_validate = AlertMixin.validate

        def counter_validate(self, raise_validation_error=True, dry_run=False):
            nonlocal validation_counter
            if not dry_run:
                model = str(ContentType.objects.get_for_model(self))
                if model not in validation_counter:
                    validation_counter[model] = 0
                validation_counter[model] += 1
            # preserve original method behavior for proper testing
            original_validate(self, raise_validation_error=raise_validation_error)

        ps_module = PsModule(
            name="rhel-8",
            bts_name="jboss",
            bts_key="RHEL",
            component_overrides="",
            default_component="kernel",
            public_description="RHEL",
            ps_product=PsProductFactory(),
            bts_groups={"public": [], "embargoed": []},
        )
        ps_module.save()
        JiraProjectFieldsFactory(
            project_key=ps_module.bts_key,
            field_id="priority",
            field_name="Priority",
            allowed_values=[
                "Blocker",
                "Critical",
                "Major",
                "Normal",
                "Minor",
                "Undefined",
            ],
        )
        JiraProjectFieldsFactory(
            project_key=ps_module.bts_key,
            field_id="security",
            field_name="Security Level",
            allowed_values=[
                "Embargoed Security Issue",
                "Red Hat Employee",
                "Red Hat Engineering Authorized",
                "Red Hat Partner",
                "Restricted",
                "Team",
            ],
        )
        JiraBugIssuetype(project=ps_module.bts_key).save()
        ps_update_stream = PsUpdateStream(
            name="rhel-8",
            ps_module=ps_module,
            default_to_ps_module=ps_module,
            active_to_ps_module=ps_module,
            version="40",
        )
        ps_update_stream.save()

        flaw_data = {
            "title": "test validations",
            "comment_zero": "this is a simple test",
            "impact": "MODERATE",
            "components": ["curl"],
            "source": "REDHAT",
            "reported_dt": "2024-08-06T00:00:00.000Z",
            "unembargo_dt": "2024-08-06T00:00:00.000Z",
            "embargoed": False,
        }

        response = auth_client().post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 201
        body = response.json()
        flaw = Flaw.objects.get(uuid=body["uuid"])

        affects_data = [
            {
                "flaw": str(flaw.uuid),
                "affectedness": "AFFECTED",
                "resolution": "DELEGATED",
                "ps_update_stream": ps_update_stream.name,
                "ps_component": "kernel",
                "impact": "MODERATE",
                "embargoed": False,
            }
        ]
        response = auth_client().post(
            f"{test_api_uri}/affects/bulk",
            affects_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200
        body = response.json()
        affect = Affect.objects.get(uuid=body["results"][0]["uuid"])

        tracker_data = {
            "affects": [affect.uuid],
            "embargoed": False,
            "ps_update_stream": ps_update_stream.name,
        }
        monkeypatch.setattr(AlertMixin, "validate", counter_validate)
        response = auth_client().post(
            f"{test_api_uri}/trackers",
            tracker_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 201

        assert len(validation_counter) == 1
        assert "osidb | Flaw" not in validation_counter
        assert validation_counter["osidb | Tracker"] == 1

    @pytest.mark.vcr
    def test_affect_validation(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_async_sync,
        enable_jira_task_sync,
        enable_jira_tracker_sync,
        jira_token,
        test_api_uri,
        monkeypatch,
    ):
        """Test that Affect endpoint only recreates alerts when needed"""
        validation_counter = {}
        original_validate = AlertMixin.validate

        def counter_validate(self, raise_validation_error=True, dry_run=False):
            nonlocal validation_counter
            if not dry_run:
                model = str(ContentType.objects.get_for_model(self))
                if model not in validation_counter:
                    validation_counter[model] = 0
                validation_counter[model] += 1
            # preserve original method behavior for proper testing
            original_validate(self, raise_validation_error=raise_validation_error)

        flaw_data = {
            "title": "test validations",
            "comment_zero": "this is a simple test",
            "impact": "MODERATE",
            "components": ["curl"],
            "source": "REDHAT",
            "reported_dt": "2024-08-06T00:00:00.000Z",
            "unembargo_dt": "2024-08-06T00:00:00.000Z",
            "embargoed": False,
        }

        response = auth_client().post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        body = response.json()
        flaw = Flaw.objects.get(uuid=body["uuid"])

        monkeypatch.setattr(AlertMixin, "validate", counter_validate)
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        JiraBugIssuetype(project=ps_module.bts_key).save()
        affects_data = [
            {
                "flaw": str(flaw.uuid),
                "affectedness": "NEW",
                "resolution": "",
                "ps_update_stream": ps_update_stream.name,
                "ps_component": "kernel",
                "impact": "MODERATE",
                "embargoed": flaw.embargoed,
            }
        ]
        response = auth_client().post(
            f"{test_api_uri}/affects/bulk",
            affects_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        # osidb/api_views.py::AffectView:bulk_post triggers flaw save
        assert len(validation_counter) == 2
        assert validation_counter["osidb | Flaw"] == 1
        assert validation_counter["osidb | Affect"] == 1
        assert response.status_code == 200
        affect = flaw.affects.first()

        affects_data[0]["uuid"] = affect.uuid
        affects_data[0]["affectedness"] = "AFFECTED"
        affects_data[0]["resolution"] = "DELEGATED"
        affects_data[0]["updated_dt"] = affect.updated_dt

        validation_counter = {}

        response = auth_client().put(
            f"{test_api_uri}/affects/bulk",
            affects_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200
        # osidb/api_views.py::AffectView:bulk_put triggers flaw save
        assert len(validation_counter) == 2
        assert validation_counter["osidb | Flaw"] == 1
        assert validation_counter["osidb | Affect"] == 1

    @pytest.mark.vcr
    def test_flaw_validation(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_async_sync,
        enable_jira_task_sync,
        enable_jira_tracker_sync,
        jira_token,
        monkeypatch,
        test_api_uri,
    ):
        """Test that Flaw endpoint only recreates alerts when needed"""
        validation_counter = {}
        original_validate = AlertMixin.validate

        def counter_validate(self, raise_validation_error=True, dry_run=False):
            nonlocal validation_counter
            if not dry_run:
                model = str(ContentType.objects.get_for_model(self))
                if model not in validation_counter:
                    validation_counter[model] = 0
                validation_counter[model] += 1
            # preserve original method behavior for proper testing
            original_validate(self, raise_validation_error=raise_validation_error)

        flaw_data = {
            "title": "test validations",
            "comment_zero": "this is a simple test",
            "impact": "MODERATE",
            "components": ["curl"],
            "source": "REDHAT",
            "reported_dt": "2024-08-06T00:00:00.000Z",
            "unembargo_dt": "2024-08-06T00:00:00.000Z",
            "embargoed": False,
        }

        monkeypatch.setattr(AlertMixin, "validate", counter_validate)
        response = auth_client().post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 201
        assert len(validation_counter) == 1
        assert validation_counter["osidb | Flaw"] == 1
        body = response.json()
        flaw = Flaw.objects.get(uuid=body["uuid"])

        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        AffectFactory(flaw=flaw, ps_update_stream=ps_update_stream.name)
        flaw_data["title"] = "new test validations"
        flaw_data["updated_dt"] = flaw.updated_dt

        validation_counter = {}

        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200
        assert len(validation_counter) == 1
        assert validation_counter["osidb | Flaw"] == 1

    @pytest.mark.vcr
    def test_alert_serialization(self, auth_client, test_api_uri):
        """Test that the AlertMixinSerializer filters out stale alerts"""

        flaw = FlawFactory(embargoed=False, source=FlawSource.REDHAT)
        alerts = Alert.objects.filter(object_id=flaw.uuid)

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")

        assert response.status_code == 200
        body = response.json()
        assert len(body["alerts"]) == alerts.count()

        # Test might finish in the same millisecond, so we need to advance time
        with freeze_time(timezone.now() + timezone.timedelta(1)):
            flaw.source = FlawSource.INTERNET
            flaw.save()

        flaw = Flaw.objects.get(uuid=flaw.uuid)
        alerts = Alert.objects.filter(object_id=flaw.uuid)
        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200
        body = response.json()
        # Alert is still on the database but is stale
        assert len(body["alerts"]) == alerts.count() - 1
