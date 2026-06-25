import pytest

from apps.taskman.service import JiraTaskmanQuerier
from apps.workflows.models import State, Workflow
from apps.workflows.serializers import WorkflowSerializer
from apps.workflows.urls import urlpatterns
from apps.workflows.workflow import WorkflowFramework
from collectors.osv.collectors import OSVCollector
from osidb.models import (
    Affect,
    AffectCVSS,
    Flaw,
    FlawAcknowledgment,
    FlawCollaborator,
    FlawComment,
    FlawCVSS,
    FlawReference,
    Tracker,
)
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
        """test unauthenticated index API endpoint"""
        response = client.get(f"{test_scheme_host}/")
        assert response.status_code == 200

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
        """test unauthenticated workflows API endpoint"""
        response = client.get(f"{test_api_uri}/workflows")
        assert response.status_code == 200

    def test_workflows_condition_in_conditions(self, auth_client, test_api_uri):
        """test that workflows with OR/AND conditions in workflow conditions serialize correctly"""
        response = auth_client().get(f"{test_api_uri}/workflows")
        assert response.status_code == 200
        body = response.json()
        rejected = next(w for w in body["workflows"] if w["name"] == "REJECTED")
        assert len(rejected["conditions"]) == 1
        condition = rejected["conditions"][0]
        assert condition["condition"] == "OR"
        assert len(condition["requirements"]) == 2

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

    def test_workflows_next_state(self, auth_client, test_api_uri):
        """test that next parameter returns the next state with requirement acceptance"""
        flaw = FlawFactory(embargoed=False, task_key="TASK-123")
        response = auth_client().get(f"{test_api_uri}/workflows/{flaw.uuid}?next=true")
        assert response.status_code == 200
        body = response.json()
        assert "next" in body
        next_state = body["next"]
        assert next_state is not None
        assert "accepts" in next_state
        assert "name" in next_state
        assert "requirements" in next_state
        for req in next_state["requirements"]:
            assert "accepts" in req

    def test_workflows_next_state_final(self, auth_client, test_api_uri):
        """test that next is null when flaw is in the final state"""
        flaw = FlawFactory(embargoed=False, task_key="TASK-123")
        FlawCollaborator.objects.create(
            flaw=flaw, label="rejected", type="workflow", contributor="test"
        )
        response = auth_client().get(f"{test_api_uri}/workflows/{flaw.uuid}?next=true")
        assert response.status_code == 200
        body = response.json()
        assert body["classification"]["workflow"] == "REJECTED"
        assert body["classification"]["state"] == "DONE"
        assert body["next"] is None

    def test_workflows_next_not_included_by_default(self, auth_client, test_api_uri):
        """test that next is not included when parameter is not set"""
        flaw = FlawFactory()
        response = auth_client().get(f"{test_api_uri}/workflows/{flaw.uuid}")
        assert response.status_code == 200
        body = response.json()
        assert "next" not in body

    def test_workflows_uuid_verbose(self, auth_client, test_api_uri):
        """test authenticated workflow classification API endpoint with verbose parameter"""
        flaw = FlawFactory(task_key="TASK-123")
        response = auth_client().get(
            f"{test_api_uri}/workflows/{flaw.uuid}?verbose=true"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert "workflows" in body

    def test_workflows_uuid_verbose_accepts(self, auth_client, test_api_uri):
        """test that verbose classification includes accepts on workflows, states, and requirements"""
        flaw = FlawFactory(embargoed=False, task_key="TASK-VERBOSE")
        response = auth_client().get(
            f"{test_api_uri}/workflows/{flaw.uuid}?verbose=true"
        )
        assert response.status_code == 200
        body = response.json()

        selected_workflow = None
        for wf in body["workflows"]:
            assert "accepts" in wf, f"workflow {wf['name']} missing accepts"
            assert isinstance(wf["accepts"], bool)
            assert "classified_state" in wf

            if wf["accepts"]:
                selected_workflow = wf
                assert wf["classified_state"] is not None
            else:
                assert wf["classified_state"] is None

            for condition in wf.get("conditions", []):
                assert "accepts" in condition
                assert list(condition.keys())[0] == "accepts"

            for state in wf["states"]:
                assert "accepts" in state, f"state {state['name']} missing accepts"
                assert isinstance(state["accepts"], bool)
                assert list(state.keys())[0] == "accepts"

                for req in state["requirements"]:
                    assert "accepts" in req, (
                        f"requirement {req['name']} missing accepts"
                    )
                    assert isinstance(req["accepts"], bool)
                    assert list(req.keys())[0] == "accepts"

        assert selected_workflow is not None
        classified = selected_workflow["classified_state"]
        assert classified == body["classification"]["state"]

    def test_workflows_verbose_rejected_workflow(self, auth_client, test_api_uri):
        """test verbose classification for a flaw in the REJECTED workflow with OR condition"""
        flaw = FlawFactory(embargoed=False, task_key="TASK-123")
        FlawCollaborator.objects.create(
            flaw=flaw, label="rejected", type="workflow", contributor="test_user"
        )
        response = auth_client().get(
            f"{test_api_uri}/workflows/{flaw.uuid}?verbose=true"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["classification"]["workflow"] == "REJECTED"
        assert body["classification"]["state"] == "DONE"

        rejected_wf = next(w for w in body["workflows"] if w["name"] == "REJECTED")
        assert rejected_wf["accepts"] is True
        assert rejected_wf["classified_state"] == "DONE"

        or_condition = rejected_wf["conditions"][0]
        assert or_condition["accepts"] is True
        assert or_condition["condition"] == "OR"
        assert len(or_condition["requirements"]) == 2
        for req in or_condition["requirements"]:
            assert "accepts" in req

    def test_workflows_verbose_condition_structure(self, auth_client, test_api_uri):
        """test that verbose classification serializes all condition types correctly"""
        flaw = FlawFactory(embargoed=False, task_key="TASK-123")
        response = auth_client().get(
            f"{test_api_uri}/workflows/{flaw.uuid}?verbose=true"
        )
        assert response.status_code == 200
        body = response.json()

        for wf in body["workflows"]:
            for condition in wf["conditions"]:
                assert "accepts" in condition
                if "condition" in condition:
                    assert condition["condition"] in ("AND", "OR")
                    assert "requirements" in condition
                    for req in condition["requirements"]:
                        assert "accepts" in req
                        assert "name" in req
                else:
                    assert "name" in condition
                    assert "description" in condition

    def test_workflows_uuid_non_existing(self, auth_client, test_api_uri):
        """test authenticated workflow classification API endpoint with non-exising flaw"""
        response = auth_client().get(
            f"{test_api_uri}/workflows/35d1ad45-0dba-41a3-bad6-5dd36d624ead"
        )
        assert response.status_code == 404

    def test_workflows_uuid_no_auth(self, client, test_api_uri):
        """test unauthenticated workflow classification API endpoint"""
        flaw = FlawFactory(embargoed=False)
        response = client.get(f"{test_api_uri}/workflows/{flaw.uuid}")
        assert response.status_code == 200

    # graph/workflows
    def test_graph_workflows(self, auth_client, test_api_uri):
        """test graph workflows endpoint renders all registered workflows"""
        response = auth_client().get(f"{test_api_uri}/graph/workflows")
        assert response.status_code == 200
        content = response.content.decode()
        assert "mermaid" in content
        for workflow in WorkflowFramework().workflows:
            assert workflow.name in content
            for state in workflow.states:
                assert state.name in content

    def test_graph_workflows_no_auth(self, client, test_api_uri):
        """test unauthenticated graph workflows endpoint"""
        response = client.get(f"{test_api_uri}/graph/workflows")
        assert response.status_code == 200

    def test_graph_classification(self, auth_client, test_api_uri):
        """test graph classification endpoint renders flaw classification"""
        flaw = FlawFactory(embargoed=False, task_key="TASK-GRAPH")
        response = auth_client().get(f"{test_api_uri}/graph/workflows/{flaw.uuid}")
        assert response.status_code == 200
        content = response.content.decode()
        assert "mermaid" in content
        # classification view renders a legend (absent in the plain workflow view)
        assert "Classified state" in content
        # flaw with no owner is classified in the NEW state
        # and the template applies per-state Mermaid styling
        assert "style NEW" in content

    # workflows/{flaw}/adjust
    @pytest.mark.enable_signals
    def test_workflows_uuid_adjusting(self, auth_client, test_api_uri):
        """
        Test adjust endpoint (DEPRECATED - NO-OP)

        The /adjust endpoint is now deprecated and performs no action.
        It returns the current stored classification without making any changes.
        """
        workflow_framework = WorkflowFramework()
        state_new = State(
            {
                "name": "NEW",
                "requirements": [],
                "jira_state": "New",
                "jira_resolution": None,
            }
        )
        state_first = State(
            {
                "name": "TRIAGE",
                "requirements": ["has comment_zero"],
                "jira_state": "To Do",
                "jira_resolution": None,
            }
        )
        state_second = State(
            {
                "name": "DONE",
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
                    "major incident state is major incident approved"
                ],  # major incident flaws are classified here
                "states": [],  # this is not valid but OK for this test
            }
        )
        workflow.states = states
        workflow_framework.register_workflow(workflow)

        flaw = FlawFactory.build(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
            task_key="TASK-123",  # Required for workflow classification
        )
        flaw.adjust_classification(save=False)
        flaw.save(raise_validation_error=False)
        AffectFactory(flaw=flaw)

        assert flaw.classification == {
            "workflow": "MAJOR_INCIDENT",
            "state": "DONE",
        }

        flaw.major_incident_state = Flaw.FlawMajorIncident.MAJOR_INCIDENT_REJECTED
        flaw.save()

        # Call the deprecated NO-OP adjust endpoint
        response = auth_client().post(f"{test_api_uri}/workflows/{flaw.uuid}/adjust")
        assert response.status_code == 200

        # Check deprecation warnings
        assert "Warning" in response
        assert "Deprecated" in response["Warning"]

        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert body["deprecated"] is True
        assert "deprecation_message" in body

        # Auto-classification reclassified the flaw from MAJOR_INCIDENT to DEFAULT
        # because major_incident_state no longer satisfies the MAJOR_INCIDENT conditions
        assert body["classification"] == {
            "workflow": "DEFAULT",
            "state": "DONE",
        }

        # Verify NO changes were made by the endpoint
        flaw_reloaded = Flaw.objects.get(pk=flaw.pk)
        assert flaw_reloaded.classification == {
            "workflow": "DEFAULT",
            "state": "DONE",
        }

    @pytest.mark.enable_signals
    def test_workflows_uuid_adjusting_no_modification(self, auth_client, test_api_uri):
        """
        test authenticated workflow classification adjusting API endpoint with no flaw modification
        """
        flaw = FlawFactory(workflow_state="NEW")
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
        set_hvac_test_env_vars,
    ):
        """
        Test promote endpoint (DEPRECATED - NO-OP)

        The /promote endpoint is now deprecated and performs no action.
        It returns the current stored classification without making any changes.
        Workflow state changes now happen automatically via signals when flaw data is saved.
        """

        def mock(self, flaw):
            return None

        monkeypatch.setattr(JiraTaskmanQuerier, "create_or_update_task", mock)
        monkeypatch.setattr(JiraTaskmanQuerier, "transition_task", mock)

        workflow_framework = WorkflowFramework()
        workflow_framework._workflows = []

        state_new = {
            "name": "NEW",
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }

        state_first = {
            "name": "SECONDARY_ASSESSMENT",
            "requirements": ["has cwe"],
            "jira_state": "In Progress",
            "jira_resolution": None,
        }

        state_second = {
            "name": "DONE",
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
        assert flaw.classification["state"] == "NEW"
        headers = {"HTTP_JIRA_API_KEY": "SECRET"}

        # Call deprecated NO-OP promote endpoint - returns 200 with current state (NEW)
        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 200
        body = response.json()
        # Check deprecation warnings
        assert "Warning" in response
        assert body["deprecated"] is True
        # Endpoint returns current state unchanged
        assert body["classification"]["state"] == "NEW"

        # Change flaw data - auto-classification advances the state
        flaw = Flaw.objects.get(pk=flaw.pk)
        flaw.cwe_id = "CWE-1"
        flaw.save()

        # Call NO-OP promote endpoint - returns auto-classified state
        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert body["deprecated"] is True
        assert body["classification"]["state"] == "SECONDARY_ASSESSMENT"

        # Change flaw data again - state advances further
        flaw = Flaw.objects.get(pk=flaw.pk)
        flaw.cve_description = "valid cve_description"
        flaw.save()

        # Call NO-OP promote endpoint - returns DONE
        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert body["deprecated"] is True
        assert body["classification"]["state"] == "DONE"

        # Call NO-OP promote endpoint again - always returns 200
        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert body["deprecated"] is True
        assert body["classification"]["state"] == "DONE"

    @pytest.mark.enable_signals
    def test_revert_endpoint(
        self,
        enable_jira_task_sync,
        monkeypatch,
        auth_client,
        test_api_uri_osidb,
        set_hvac_test_env_vars,
    ):
        """
        Test revert endpoint (DEPRECATED - NO-OP)

        The /revert endpoint is now deprecated and performs no action.
        It returns the current stored classification without making any changes.
        """

        def mock(self, flaw):
            return None

        monkeypatch.setattr(JiraTaskmanQuerier, "create_or_update_task", mock)
        monkeypatch.setattr(JiraTaskmanQuerier, "transition_task", mock)

        workflow_framework = WorkflowFramework()
        workflow_framework._workflows = []

        state_new = {
            "name": "NEW",
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }

        state_first = {
            "name": "SECONDARY_ASSESSMENT",
            "requirements": ["has cwe"],
            "jira_state": "In Progress",
            "jira_resolution": None,
        }

        state_second = {
            "name": "DONE",
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

        # Create flaw in DONE state with all requirements met
        flaw = FlawFactory(
            cwe_id="CWE-1",
            cve_description="valid cve_description",
            task_key="OSIM-123",
            workflow_state="DONE",
        )
        AffectFactory(flaw=flaw)

        assert flaw.classification["workflow"] == "DEFAULT"
        assert flaw.classification["state"] == "DONE"

        # Call deprecated NO-OP revert endpoint - returns current state (DONE)
        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/revert",
            data={},
            format="json",
        )
        assert response.status_code == 200
        body = response.json()
        assert "Warning" in response
        assert body["deprecated"] is True
        # Returns current state unchanged (DONE, not SECONDARY_ASSESSMENT)
        assert body["classification"]["state"] == "DONE"

        # Call NO-OP revert again - still returns DONE
        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/revert",
            data={},
            format="json",
        )
        assert response.status_code == 200
        body = response.json()
        assert body["deprecated"] is True
        # Still DONE (not NEW) - no state changes from endpoint
        assert body["classification"]["state"] == "DONE"

        # Call NO-OP revert again - always returns 200 (not 409)
        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/revert",
            data={},
            format="json",
        )
        assert response.status_code == 200
        body = response.json()
        assert body["deprecated"] is True
        # No validation errors - just returns current state
        assert body["classification"]["state"] == "DONE"

    @pytest.mark.enable_signals
    def test_reset_endpoint(
        self,
        enable_jira_task_sync,
        monkeypatch,
        auth_client,
        test_api_uri_osidb,
        set_hvac_test_env_vars,
    ):
        """
        Test reset endpoint (DEPRECATED - NO-OP)

        The /reset endpoint is now deprecated and performs no action.
        It returns the current stored classification without making any changes.
        """

        def mock(self, flaw):
            return None

        monkeypatch.setattr(JiraTaskmanQuerier, "create_or_update_task", mock)
        monkeypatch.setattr(JiraTaskmanQuerier, "transition_task", mock)

        workflow_framework = WorkflowFramework()
        workflow_framework._workflows = []

        # Create default workflow with multiple states
        state_new = {
            "name": "NEW",
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }

        state_triage = {
            "name": "TRIAGE",
            "requirements": ["has cwe"],
            "jira_state": "To Do",
            "jira_resolution": None,
        }

        state_done = {
            "name": "DONE",
            "requirements": ["has cve_description"],
            "jira_state": "Closed",
            "jira_resolution": "Done",
        }

        default_workflow = Workflow(
            {
                "name": "DEFAULT",
                "description": "default workflow",
                "priority": 0,
                "conditions": [],
                "states": [state_new, state_triage, state_done],
            }
        )

        # Create rejected workflow
        state_rejected = {
            "name": "DONE",
            "requirements": [],
            "jira_state": "Closed",
            "jira_resolution": "Won't Do",
        }

        reject_workflow = Workflow(
            {
                "name": "REJECTED",
                "description": "rejected workflow",
                "priority": 1,
                "conditions": ["has label rejected"],
                "states": [state_rejected],
            }
        )

        workflow_framework.register_workflow(default_workflow)
        workflow_framework.register_workflow(reject_workflow)

        # Test 1: Call NO-OP reset from DONE state - returns current state (DONE)
        flaw = FlawFactory(
            cwe_id="CWE-1",
            cve_description="valid cve_description",
            task_key="OSIM-123",
            workflow_state="DONE",
            workflow_name="DEFAULT",
        )
        AffectFactory(flaw=flaw)

        assert flaw.classification["workflow"] == "DEFAULT"
        assert flaw.classification["state"] == "DONE"

        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/reset",
            data={},
            format="json",
        )
        assert response.status_code == 200
        body = response.json()
        assert "Warning" in response
        assert body["deprecated"] is True
        # Returns current state unchanged (DONE, not reset to NEW)
        assert body["classification"]["workflow"] == "DEFAULT"
        assert body["classification"]["state"] == "DONE"

        # Test 2: Auto-classification assigns non-rejected flaw to DEFAULT
        flaw = FlawFactory(
            cwe_id="CWE-1",
            cve_description="valid cve_description",
            task_key="OSIM-124",
            workflow_state="DONE",
            workflow_name="DEFAULT",
        )
        AffectFactory(flaw=flaw)

        assert flaw.classification["workflow"] == "DEFAULT"
        assert flaw.classification["state"] == "DONE"

        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/reset",
            data={},
            format="json",
        )
        assert response.status_code == 200
        body = response.json()
        assert body["deprecated"] is True
        assert body["classification"]["workflow"] == "DEFAULT"
        assert body["classification"]["state"] == "DONE"

        # Test 3: Call NO-OP reset from NEW state - returns current state
        flaw = FlawFactory(
            cwe_id="",
            cve_description="",
            task_key="OSIM-125",
            workflow_state="NEW",
            workflow_name="DEFAULT",
        )
        AffectFactory(flaw=flaw)

        assert flaw.classification["workflow"] == "DEFAULT"
        assert flaw.classification["state"] == "NEW"

        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/reset",
            data={},
            format="json",
        )
        assert response.status_code == 200
        body = response.json()
        assert body["deprecated"] is True
        # Returns current state unchanged (already NEW)
        assert body["classification"]["workflow"] == "DEFAULT"
        assert body["classification"]["state"] == "NEW"

    @pytest.mark.enable_signals
    def test_reject_endpoint(
        self,
        monkeypatch,
        auth_client,
        test_api_uri_osidb,
        set_hvac_test_env_vars,
    ):
        """
        Test reject endpoint (DEPRECATED - NO-OP)

        The /reject endpoint is now deprecated and performs no action.
        It returns the current stored classification without making any changes.
        No Jira comment is created.
        """

        # This mock should never be called since endpoint is NO-OP
        def mock_create_comment(self, issue_key: str, body: str):
            raise AssertionError(
                "create_comment should not be called - endpoint is NO-OP"
            )

        monkeypatch.setattr(JiraTaskmanQuerier, "create_comment", mock_create_comment)

        workflow_framework = WorkflowFramework()
        workflow_framework._workflows = []

        state_new = {
            "name": "NEW",
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }

        state_first = {
            "name": "SECONDARY_ASSESSMENT",
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
            "name": "DONE",
            "requirements": [],
            "jira_state": "Closed",
            "jira_resolution": "Won't Do",
        }
        reject_workflow = Workflow(
            {
                "name": "REJECTED",
                "description": "random description",
                "priority": 1,
                "conditions": ["has label rejected"],
                "states": [state_reject],
            }
        )
        workflow_framework.register_workflow(workflow)
        workflow_framework.register_workflow(reject_workflow)

        flaw = FlawFactory(cwe_id="", task_key="OSIM-123")
        AffectFactory(flaw=flaw)

        # Flaw has task_key, so it gets auto-classified to DEFAULT on creation
        assert flaw.classification["workflow"] == "DEFAULT"
        assert flaw.classification["state"] == "NEW"
        headers = {"HTTP_JIRA_API_KEY": "SECRET"}

        # Test 1: Call without reason - NO-OP endpoint accepts any body
        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/reject",
            data={"reason": "This was a spam."},
            format="json",
            **headers,
        )

        body = response.json()

        assert response.status_code == 200
        assert "Warning" in response
        assert body["deprecated"] is True
        # Returns current state unchanged (DEFAULT/NEW, not REJECTED)
        # No Jira comment is created (mock would raise AssertionError if called)
        assert body["classification"]["workflow"] == "DEFAULT"
        assert body["classification"]["state"] == "NEW"


class TestFlawDraft:
    # models to check audit ACLs for
    models_list = [
        Flaw,
        FlawAcknowledgment,
        FlawComment,
        FlawCVSS,
        FlawReference,
        Affect,
        AffectCVSS,
        Tracker,
    ]

    def mock_create_task(self, flaw):
        return "OSIM-123"

    def assert_audit_acls(self, model, expected_read, expected_write):
        """helper to assert audit ACLs for all instances of a model"""
        for instance in model.objects.all():
            for audit_event in instance.events.all():
                assert audit_event.acl_read == expected_read
                assert audit_event.acl_write == expected_write

    @pytest.mark.vcr
    def test_promote(
        self,
        enable_jira_task_sync,
        monkeypatch,
        auth_client,
        test_api_uri_osidb,
        jira_token,
        set_hvac_test_env_vars,
        public_read_groups,
        public_write_groups,
        internal_read_groups,
        internal_write_groups,
    ):
        """
        Test promote endpoint with ACLs (DEPRECATED - NO-OP)

        The /promote endpoint is now deprecated and performs no action.
        It returns the current stored classification without making any changes.
        ACL changes are triggered by automatic classification via signals when flaw data is saved.
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
        assert flaw.classification["state"] == "NEW"
        assert flaw.task_key == "OSIM-123"
        assert flaw.is_internal

        # set owner and components to comply with TRIAGE requirements
        # This save() will trigger automatic classification via signals
        flaw.owner = "Alice"
        flaw.components.append("component")
        flaw.save(raise_validation_error=False)

        # let us expect that somebody created Affect and Tracker for an un-promoted flaw by mistake
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
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
        assert flaw.affects.first().tracker is not None
        assert flaw.affects.first().tracker.is_internal

        # Reload flaw to see current state
        flaw = Flaw.objects.get(pk=flaw.pk)
        current_workflow = flaw.classification["workflow"]
        current_state = flaw.classification["state"]

        headers = {"HTTP_JIRA_API_KEY": jira_token}
        # Call NO-OP promote endpoint - returns current state
        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert body["deprecated"] is True
        # Returns whatever the current state is (not changed by this endpoint)
        assert body["classification"]["workflow"] == current_workflow
        assert body["classification"]["state"] == current_state

        # Verify endpoint made no changes
        flaw = Flaw.objects.get(pk=flaw.pk)
        assert flaw.classification["workflow"] == current_workflow
        assert flaw.classification["state"] == current_state
        assert flaw.task_key == "OSIM-123"

        # ACLs remain as they were (no workflow transition from endpoint)
        # The flaw stays internal because no state change occurred

        # Call NO-OP promote again - still returns current state
        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert body["deprecated"] is True
        # Still returns same state - endpoint makes no changes
        assert body["classification"]["workflow"] == current_workflow
        assert body["classification"]["state"] == current_state

    @pytest.mark.vcr
    def test_reject(
        self,
        enable_jira_task_sync,
        monkeypatch,
        auth_client,
        test_api_uri_osidb,
        jira_token,
        set_hvac_test_env_vars,
        internal_read_groups,
        internal_write_groups,
    ):
        """
        Test reject endpoint with ACLs (DEPRECATED - NO-OP)

        The /reject endpoint is now deprecated and performs no action.
        It returns the current stored classification without making any changes.
        No Jira comment is created.
        """
        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", self.mock_create_task
        )

        # This mock should never be called since endpoint is NO-OP
        def mock_create_comment(self, issue_key: str, body: str):
            raise AssertionError(
                "create_comment should not be called - endpoint is NO-OP"
            )

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
        assert flaw.classification["state"] == "NEW"
        assert flaw.is_internal is True

        headers = {"HTTP_JIRA_API_KEY": jira_token}
        # Call NO-OP reject endpoint - returns current state (empty workflow, NEW state)
        response = auth_client().post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/reject",
            data={"reason": "Not shipped."},
            format="json",
            **headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert body["deprecated"] is True
        # Returns current state unchanged (not REJECTED)
        # No Jira comment is created (mock would raise AssertionError if called)
        assert body["classification"]["workflow"] == "DEFAULT"
        assert body["classification"]["state"] == "NEW"

        # Verify endpoint made no changes to flaw in database
        flaw = Flaw.objects.get(pk=flaw.pk)
        assert flaw.classification["workflow"] == "DEFAULT"
        assert flaw.classification["state"] == "NEW"
        # ACLs remain internal (no state change means no ACL change)
        assert flaw.is_internal is True

        # Audit ACLs remain internal (no workflow transition occurred)
        for model in self.models_list:
            self.assert_audit_acls(model, internal_read_groups, internal_write_groups)
