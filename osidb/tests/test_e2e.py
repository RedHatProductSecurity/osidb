import pytest
from django.utils import timezone
from freezegun import freeze_time

from apps.taskman.service import JiraTaskmanQuerier
from apps.trackers.constants import TRACKERS_API_VERSION
from apps.workflows.models import Workflow
from apps.workflows.workflow import WorkflowFramework, WorkflowModel
from collectors.jiraffe.collectors import JiraTrackerCollector
from osidb.models import Affect, Flaw, PsUpdateStream, Tracker
from osidb.sync_manager import (
    BZSyncManager,
    JiraTaskSyncManager,
    JiraTrackerLinkManager,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def test_trackers_api_uri() -> str:
    return f"http://osidb-service:8000/trackers/api/{TRACKERS_API_VERSION}"


def tzdatetime(*args):
    return timezone.datetime(*args, tzinfo=timezone.get_current_timezone())


class TestE2E:
    """
    Test complete use case scenarios with all sync enabled,
    relying on REST API to simulate user behavior
    """

    @pytest.mark.parametrize("embargoed", [True, False])
    @freeze_time(tzdatetime(2024, 8, 6))
    @pytest.mark.vcr
    def test_flaw_affect_tracker(
        self,
        auth_client,
        bugzilla_token,
        client,
        embargoed,
        enable_bz_async_sync,
        enable_jira_task_async_sync,
        enable_jira_tracker_sync,
        jira_token,
        monkeypatch,
        setup_sample_external_resources,
        test_api_uri,
        test_trackers_api_uri,
    ):
        """
        Test a user can create a flaw from scratch, including:
        - create flaw and sync with bz and jira task
        - create affect
        - create async tracker
        - collect tracker data and link with affect
        - validate access rights in all steps
        """
        unembargoed_dt = "2024-08-06T00:00:00.000Z"
        expected_status = 200
        if embargoed:
            unembargoed_dt = "2024-08-07T00:00:00.000Z"
            expected_status = 404

        # Simulates user behavior for task sync
        monkeypatch.setattr(JiraTaskmanQuerier, "is_service_account", lambda x: False)

        # 1) create flaw
        flaw_data = {
            "title": "test validations",
            "comment_zero": "this is a simple test",
            "impact": "CRITICAL",
            "components": ["curl"],
            "source": "REDHAT",
            "reported_dt": "2024-08-06T00:00:00.000Z",
            "unembargo_dt": unembargoed_dt,
            "embargoed": embargoed,
        }

        response = auth_client().post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        # 1.1) validade flaw was created and bz sync is scheduled
        assert response.status_code == 201
        body = response.json()
        assert BZSyncManager.objects.get(sync_id=body["uuid"])
        assert JiraTaskSyncManager.objects.get(sync_id=body["uuid"])

        # 1.2) synchronously bzsync instead of waiting on Celery
        flaw = Flaw.objects.get(uuid=body["uuid"])
        flaw._perform_bzsync(bz_api_key=bugzilla_token)
        flaw._create_or_update_task(jira_token)

        # 1.3) validate access control
        response = client.get(
            f"{test_api_uri}/flaws/{flaw.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == expected_status
        if not embargoed:
            assert response.json()["title"] == "test validations"
            assert "curl" in response.json()["components"]
            assert response.json()["meta_attr"]["bz_id"]

        # 2) get valid external data
        ps_update_streams = PsUpdateStream.objects.filter(
            active_to_ps_module__bts_name="jboss"
        ).order_by("name")[:2]
        ps_module = ps_update_streams[0].active_to_ps_module
        ps_module.private_trackers_allowed = True
        ps_module.save()

        # 3) create affect
        affects_data = [
            {
                "flaw": str(flaw.uuid),
                "affectedness": "AFFECTED",
                "resolution": "DELEGATED",
                "ps_module": ps_module.name,
                "ps_component": ps_module.default_component,
                "impact": "CRITICAL",
                "embargoed": embargoed,
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

        # 3.1) validate access control for affects
        response = client.get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == expected_status
        if not embargoed:
            assert len(response.json()["affects"]) == 1

        # 4) get and validate trackers suggestions
        response = auth_client().post(
            f"{test_trackers_api_uri}/file",
            data={"flaw_uuids": [flaw.uuid]},
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        body = response.json()
        comp = body["modules_components"][0]
        assert comp["ps_module"] == ps_module.name
        assert comp["ps_component"] == ps_module.default_component

        suggested_trackers = [stream["ps_update_stream"] for stream in comp["streams"]]
        assert ps_update_streams[0].name in suggested_trackers
        assert ps_update_streams[1].name in suggested_trackers

        # 5) create trackers
        for stream in ps_update_streams:
            tracker_data = {
                "affects": [affect.uuid],
                "embargoed": flaw.embargoed,
                "ps_update_stream": stream.name,
            }
            response = auth_client().post(
                f"{test_api_uri}/trackers",
                tracker_data,
                format="json",
                HTTP_BUGZILLA_API_KEY=bugzilla_token,
                HTTP_JIRA_API_KEY=jira_token,
            )
            assert response.status_code == 201
            body = response.json()
            assert body["external_system_id"]
            tracker_id = body["external_system_id"]
            assert body["type"] == Tracker.TrackerType.JIRA
            assert body["ps_update_stream"] == stream.name
            jc = JiraTrackerCollector()
            jc.collect(tracker_id)
            JiraTrackerLinkManager.link_tracker_with_affects(tracker_id)

        # 5.1) validate access control for trackers
        response = client.get(
            f"{test_api_uri}/flaws/{flaw.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == expected_status
        if not embargoed:
            assert len(response.json()["trackers"]) == 2
            assert len(response.json()["affects"]) == 1
            assert len(response.json()["affects"][0]["trackers"]) == 2
            assert "curl" in response.json()["components"]
            assert response.json()["meta_attr"]["bz_id"]

        # 6) validate users can promote flaws
        # 6.1) setup workflows for test
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
            "requirements": ["has title"],
            "jira_state": "In Progress",
            "jira_resolution": None,
        }

        workflow = Workflow(
            {
                "name": "DEFAULT",
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [state_new, state_first],
            }
        )
        workflow_framework.register_workflow(workflow)

        # 6.2) promote flaw
        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200

        # 6.3) validate promotion were applied
        response = auth_client().get(
            f"{test_api_uri}/flaws/{flaw.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 200
        body = response.json()
        assert (
            body["classification"]["state"]
            == WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT
        )

        # 7) validate users can unembargo flaw
        if embargoed:
            with freeze_time(tzdatetime(2024, 8, 15)):
                flaw.refresh_from_db()
                flaw_data = {
                    "title": "test validations",
                    "comment_zero": "this is a simple test",
                    "impact": "CRITICAL",
                    "components": ["curl"],
                    "source": "REDHAT",
                    "reported_dt": "2024-08-06T00:00:00.000Z",
                    "unembargo_dt": unembargoed_dt,
                    "updated_dt": flaw.updated_dt,
                    "embargoed": False,
                }
                response = auth_client().put(
                    f"{test_api_uri}/flaws/{flaw.uuid}",
                    flaw_data,
                    format="json",
                    HTTP_BUGZILLA_API_KEY=bugzilla_token,
                    HTTP_JIRA_API_KEY=jira_token,
                )
                assert response.status_code == 200

        response = client.get(
            f"{test_api_uri}/flaws/{flaw.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 200
        body = response.json()
        assert len(body["trackers"]) == 2
        assert len(body["affects"]) == 1
        assert len(body["affects"][0]["trackers"]) == 2
        assert "curl" in body["components"]
        assert body["meta_attr"]["bz_id"]
        # test modifications made while embargoed are now public
        assert any(
            h["pgh_diff"] and "task_key" in h["pgh_diff"] for h in body["history"]
        )
