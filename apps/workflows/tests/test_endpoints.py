import pytest
from django.conf import settings

from apps.taskman.service import JiraTaskmanQuerier
from apps.workflows.models import State, Workflow
from apps.workflows.serializers import WorkflowSerializer
from apps.workflows.urls import urlpatterns
from apps.workflows.workflow import WorkflowFramework, WorkflowModel
from collectors.osv.collectors import OSVCollector
from osidb.core import set_user_acls
from osidb.models import Affect, Flaw, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestEndpoints(object):
    # workflows/
    def test_index_auth(self, auth_client, test_scheme_host):
        """test authenticated index API endpoint"""
        response = auth_client().get(f"{test_scheme_host}/")
        assert response.status_code == 200
        body = response.json()
        assert body["index"] == [f"/{url.pattern}" for url in urlpatterns]

    def test_index_no_auth(self, client, test_scheme_host):
        """test authenticated index API endpoint without authenticating"""
        response = client.get(f"{test_scheme_host}/")
        assert response.status_code == 401

    # workflows/healthy
    def test_health(self, client, test_scheme_host):
        """test health API endpoint"""
        response = client.get(f"{test_scheme_host}/healthy")
        assert response.status_code == 200

    # workflows
    def test_workflows_auth(self, auth_client, test_api_uri):
        """test authenticated workflows API endpoint"""
        response = auth_client().get(f"{test_api_uri}/workflows")
        assert response.status_code == 200
        body = response.json()
        workflows = WorkflowSerializer(WorkflowFramework().workflows, many=True).data
        assert body["workflows"] == workflows

    def test_workflows_no_auth(self, client, test_api_uri):
        """test authenticated workflows API endpoint without authenticating"""
        response = client.get(f"{test_api_uri}/workflows")
        assert response.status_code == 401

    def test_workflows_cve(self, auth_client, test_api_uri):
        """test authenticated workflow classification API endpoint"""
        flaw = FlawFactory()
        response = auth_client().get(f"{test_api_uri}/workflows/{flaw.cve_id}")
        assert response.status_code == 200
        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert "workflows" not in body

    # workflows/{flaw}
    def test_workflows_uuid(self, auth_client, test_api_uri):
        """test authenticated workflow classification API endpoint"""
        flaw = FlawFactory()
        response = auth_client().get(f"{test_api_uri}/workflows/{flaw.uuid}")
        assert response.status_code == 200
        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert "workflows" not in body

    def test_workflows_uuid_verbose(self, auth_client, test_api_uri):
        """test authenticated workflow classification API endpoint with verbose parameter"""
        flaw = FlawFactory()
        response = auth_client().get(
            f"{test_api_uri}/workflows/{flaw.uuid}?verbose=true"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert "workflows" in body

    def test_workflows_uuid_non_existing(self, auth_client, test_api_uri):
        """test authenticated workflow classification API endpoint with non-exising flaw"""
        response = auth_client().get(
            f"{test_api_uri}/workflows/35d1ad45-0dba-41a3-bad6-5dd36d624ead"
        )
        assert response.status_code == 404

    def test_workflows_uuid_no_auth(self, client, test_api_uri):
        """test authenticated workflow classification API endpoint without authenticating"""
        flaw = FlawFactory()
        response = client.get(f"{test_api_uri}/workflows/{flaw.uuid}")
        assert response.status_code == 401

    # workflows/{flaw}/adjust
    @pytest.mark.enable_signals
    def test_workflows_uuid_adjusting(self, auth_client, test_api_uri):
        """test flaw classification adjustion after metadata change"""
        workflow_framework = WorkflowFramework()
        state_new = State(
            {
                "name": WorkflowModel.WorkflowState.NEW,
                "requirements": [],
                "jira_state": "New",
                "jira_resolution": None,
            }
        )
        state_first = State(
            {
                "name": WorkflowModel.WorkflowState.TRIAGE,
                "requirements": ["has comment_zero"],
                "jira_state": "To Do",
                "jira_resolution": None,
            }
        )
        state_second = State(
            {
                "name": WorkflowModel.WorkflowState.DONE,
                "requirements": ["has title"],
                "jira_state": "In Progress",
                "jira_resolution": None,
            }
        )

        states = [state_new, state_first, state_second]

        # initialize default workflow first so there is
        # always some workflow to classify the flaw in
        workflow = Workflow(
            {
                "name": "DEFAULT",
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [],  # this is not valid but OK for this test
            }
        )
        workflow.states = states
        workflow_framework.register_workflow(workflow)

        # major incident workflow
        workflow = Workflow(
            {
                "name": "MAJOR_INCIDENT",
                "description": "random description",
                "priority": 1,  # is more prior than default one
                "conditions": [
                    "major incident state is approved"
                ],  # major incident flaws are classified here
                "states": [],  # this is not valid but OK for this test
            }
        )
        workflow.states = states
        workflow_framework.register_workflow(workflow)

        flaw = FlawFactory.build(major_incident_state=Flaw.FlawMajorIncident.APPROVED)
        flaw.adjust_classification(save=False)
        flaw.save(raise_validation_error=False)
        AffectFactory(flaw=flaw)

        assert flaw.classification == {
            "workflow": "MAJOR_INCIDENT",
            "state": "DONE",
        }

        flaw.major_incident_state = Flaw.FlawMajorIncident.NOVALUE
        flaw.save()

        response = auth_client().post(f"{test_api_uri}/workflows/{flaw.uuid}/adjust")
        assert response.status_code == 200
        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert body["classification"] == {
            "workflow": "DEFAULT",
            "state": "DONE",
        }

        # reload flaw DB
        flaw = Flaw.objects.get(pk=flaw.pk)
        assert flaw.classification == {
            "workflow": "DEFAULT",
            "state": "DONE",
        }

    @pytest.mark.enable_signals
    def test_workflows_uuid_adjusting_no_modification(self, auth_client, test_api_uri):
        """
        test authenticated workflow classification adjusting API endpoint with no flaw modification
        """
        flaw = FlawFactory(workflow_state=WorkflowModel.WorkflowState.NEW)
        response = auth_client().post(f"{test_api_uri}/workflows/{flaw.uuid}/adjust")
        assert response.status_code == 200
        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert body["classification"] == flaw.classification

    def test_workflows_uuid_adjust_non_existing(self, auth_client, test_api_uri):
        """
        test authenticated workflow classification adjusting API endpoint with non-exising flaw
        """
        response = auth_client().post(
            f"{test_api_uri}/workflows/35d1ad45-0dba-41a3-bad6-5dd36d624ead/adjust"
        )
        assert response.status_code == 404

    def test_workflows_uuid_adjust_no_auth(self, client, test_api_uri):
        """
        test authenticated workflow classification adjusting API endpoint without authenticating
        """
        flaw = FlawFactory()
        response = client.post(f"{test_api_uri}/workflows/{flaw.uuid}/adjust")
        assert response.status_code == 401

    @pytest.mark.enable_signals
    def test_promote_endpoint(
        self,
        enable_jira_task_sync,
        monkeypatch,
        auth_client,
        test_api_uri_osidb,
    ):
        """test flaw state promotion after data change"""

        def mock(self, flaw):
            return None

        monkeypatch.setattr(JiraTaskmanQuerier, "create_or_update_task", mock)
        monkeypatch.setattr(JiraTaskmanQuerier, "transition_task", mock)

        workflow_framework = WorkflowFramework()
        workflow_framework._workflows = []

        state_new = {
            "name": WorkflowModel.WorkflowState.NEW,
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }

        state_first = {
            "name": WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT,
            "requirements": ["has cwe"],
            "jira_state": "In Progress",
            "jira_resolution": None,
        }

        state_second = {
            "name": WorkflowModel.WorkflowState.DONE,
            "requirements": ["has cve_description"],
            "jira_state": "Closed",
            "jira_resolution": "Done",
        }

        workflow = Workflow(
            {
                "name": "DEFAULT",
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [state_new, state_first, state_second],
            }
        )
        workflow_framework.register_workflow(workflow)

        flaw = FlawFactory(cwe_id="", cve_description="", task_key="OSIM-123")
        AffectFactory(flaw=flaw)

        assert flaw.classification["workflow"] == "DEFAULT"
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.NEW
        headers = {"HTTP_JIRA_API_KEY": "SECRET"}
        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 409
        body = response.json()
        assert "has cwe" in body["errors"]

        flaw = Flaw.objects.get(pk=flaw.pk)
        flaw.cwe_id = "CWE-1"
        flaw.save()

        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert (
            body["classification"]["state"]
            == WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT
        )

        flaw = Flaw.objects.get(pk=flaw.pk)
        flaw.cve_description = "valid cve_description"
        flaw.save()

        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        flaw = Flaw.objects.get(pk=flaw.pk)
        assert response.status_code == 200
        body = response.json()
        assert body["classification"]["state"] == WorkflowModel.WorkflowState.DONE

        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 409
        body = response.json()
        assert "already in the last state" in body["errors"]

    @pytest.mark.enable_signals
    def test_reject_endpoint(
        self,
        monkeypatch,
        auth_client,
        test_api_uri_osidb,
    ):
        """test flaw state promotion after data change"""

        def mock_create_comment(self, issue_key: str, body: str):
            return

        monkeypatch.setattr(JiraTaskmanQuerier, "create_comment", mock_create_comment)

        workflow_framework = WorkflowFramework()
        workflow_framework._workflows = []

        state_new = {
            "name": WorkflowModel.WorkflowState.NEW,
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }

        state_first = {
            "name": WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT,
            "requirements": ["has cwe"],
            "jira_state": "To Do",
            "jira_resolution": None,
        }

        workflow = Workflow(
            {
                "name": "DEFAULT",
                "description": "random description",
                "priority": 1,
                "conditions": [],
                "states": [state_new, state_first],
            }
        )
        state_reject = {
            "name": WorkflowModel.WorkflowState.REJECTED,
            "requirements": [],
            "jira_state": "Closed",
            "jira_resolution": "Won't Do",
        }
        reject_workflow = Workflow(
            {
                "name": "REJECTED",
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [state_reject],
            }
        )
        workflow_framework.register_workflow(workflow)
        workflow_framework.register_workflow(reject_workflow)

        flaw = FlawFactory(cwe_id="")
        AffectFactory(flaw=flaw)

        assert flaw.classification["workflow"] == "DEFAULT"
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.NOVALUE
        headers = {"HTTP_JIRA_API_KEY": "SECRET"}

        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/reject",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 400
        # must reset ACLs to access Flaw
        set_user_acls(settings.ALL_GROUPS)
        flaw = Flaw.objects.get(pk=flaw.pk)
        assert flaw.classification["workflow"] == "DEFAULT"
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.NOVALUE

        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/reject",
            data={"reason": "This was a spam."},
            format="json",
            **headers,
        )

        body = response.json()

        assert response.status_code == 200
        assert body["classification"]["workflow"] == "REJECTED"
        assert body["classification"]["state"] == WorkflowModel.WorkflowState.REJECTED


class TestFlawDraft:
    def mock_create_task(self, flaw):
        return "OSIM-123"

    @pytest.mark.vcr
    def test_promote(
        self,
        enable_jira_task_sync,
        monkeypatch,
        auth_client,
        test_api_uri_osidb,
        jira_token,
    ):
        """
        test that ACLs are set to public when promoting a flaw draft
        """
        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", self.mock_create_task
        )

        osv_id = "GHSA-3hwm-922r-47hw"
        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = None
        osvc.collect(osv_id=osv_id)

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.classification["workflow"] == "DEFAULT"
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.NEW
        assert flaw.task_key == "OSIM-123"
        assert flaw.is_internal

        # set owner to comply with TRIAGE requirements
        flaw.owner = "Alice"
        flaw.save(raise_validation_error=False)

        # let us expect that somebody created Affect and Tracker for an un-promoted flaw by mistake
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            ps_component="component",
        )
        TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.JIRA,
            acl_read=affect.acl_read,
            acl_write=affect.acl_write,
        )
        # and thus they have incorrect internal ACLs
        assert flaw.affects.first().is_internal
        assert flaw.affects.first().trackers.first().is_internal

        headers = {"HTTP_JIRA_API_KEY": jira_token}
        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert body["classification"]["workflow"] == "DEFAULT"
        assert body["classification"]["state"] == WorkflowModel.WorkflowState.TRIAGE

        flaw.refresh_from_db()
        assert flaw.classification["workflow"] == "DEFAULT"
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.TRIAGE
        assert flaw.task_key == "OSIM-123"

        # check that a flaw and related objects (except for snippets)
        # still have internal ACLs as we publish only after the triage
        assert flaw.is_internal
        assert flaw.affects.count() == 1
        assert flaw.affects.first().is_internal
        assert flaw.affects.first().trackers.count() == 1
        assert flaw.affects.first().trackers.first().is_internal
        assert flaw.cvss_scores.count() == 1
        assert flaw.cvss_scores.first().is_internal
        assert flaw.references.count() == 5
        for r in flaw.references.all():
            assert r.is_internal
        assert flaw.snippets.count() == 1
        assert flaw.snippets.first().is_internal

        # one more promote to complete the triage
        headers = {"HTTP_JIRA_API_KEY": jira_token}
        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert body["classification"]["workflow"] == "DEFAULT"
        assert (
            body["classification"]["state"]
            == WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        )

        flaw.refresh_from_db()
        assert flaw.classification["workflow"] == "DEFAULT"
        assert (
            flaw.classification["state"]
            == WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        )
        assert flaw.task_key == "OSIM-123"

        # check that a flaw and related objects (except for snippets) have public ACLs
        assert flaw.is_public
        assert flaw.affects.count() == 1
        assert flaw.affects.first().is_public
        assert flaw.affects.first().trackers.count() == 1
        assert flaw.affects.first().trackers.first().is_public
        assert flaw.cvss_scores.count() == 1
        assert flaw.cvss_scores.first().is_public
        assert flaw.references.count() == 5
        for r in flaw.references.all():
            assert r.is_public
        assert flaw.snippets.count() == 1
        assert flaw.snippets.first().is_internal

    @pytest.mark.vcr
    def test_reject(
        self,
        enable_jira_task_sync,
        monkeypatch,
        auth_client,
        test_api_uri_osidb,
        jira_token,
    ):
        """
        test that ACLs are still set to internal when rejecting a flaw draft
        """
        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", self.mock_create_task
        )

        def mock_create_comment(self, issue_key: str, body: str):
            return

        monkeypatch.setattr(JiraTaskmanQuerier, "create_comment", mock_create_comment)

        osv_id = "GHSA-3hwm-922r-47hw"
        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = None
        osvc.collect(osv_id=osv_id)

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.task_key == "OSIM-123"
        assert flaw.classification["workflow"] == "DEFAULT"
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.NEW
        assert flaw.is_internal is True

        headers = {"HTTP_JIRA_API_KEY": jira_token}
        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/reject",
            data={"reason": "Not shipped."},
            format="json",
            **headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert body["classification"]["workflow"] == "REJECTED"
        assert body["classification"]["state"] == WorkflowModel.WorkflowState.REJECTED

        flaw.refresh_from_db()
        assert flaw.classification["workflow"] == "REJECTED"
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.REJECTED
        # check that a flaw still has internal ACLs
        assert flaw.is_internal is True
