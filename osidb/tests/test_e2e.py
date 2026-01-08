import uuid
from pathlib import Path

import pytest
from django.utils import timezone
from freezegun import freeze_time

from apps.taskman.service import JiraTaskmanQuerier
from apps.trackers.constants import TRACKERS_API_VERSION
from apps.workflows.models import Workflow
from apps.workflows.workflow import WorkflowFramework, WorkflowModel
from collectors.cveorg import tests as cveorg_tests
from collectors.cveorg.collectors import CVEorgCollector
from collectors.cveorg.models import Keyword
from collectors.jiraffe.collectors import (
    JiraTrackerCollector,
    JiraTrackerDownloadManager,
)
from osidb.models import Affect, Flaw, PsUpdateStream, Snippet, Tracker
from osidb.sync_manager import (
    BZSyncManager,
    JiraTaskSyncManager,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def test_trackers_api_uri() -> str:
    return f"http://osidb-service:8000/trackers/api/{TRACKERS_API_VERSION}"


@pytest.fixture()
def mock_keywords() -> None:
    """
    Set testing keywords to mock the ones from the ps-constants repository.
    """
    Keyword(keyword="kernel", type=Keyword.Type.ALLOWLIST).save()
    Keyword(keyword=r"(?:\W|^)\.NET\b", type=Keyword.Type.ALLOWLIST_SPECIAL_CASE).save()
    Keyword(keyword=".*plugin.*for WordPress", type=Keyword.Type.BLOCKLIST).save()
    Keyword(keyword="Cisco", type=Keyword.Type.BLOCKLIST).save()
    Keyword(keyword="IBM Tivoli", type=Keyword.Type.BLOCKLIST).save()
    Keyword(keyword="iTunes", type=Keyword.Type.BLOCKLIST).save()
    Keyword(keyword="iOS", type=Keyword.Type.BLOCKLIST_SPECIAL_CASE).save()


@pytest.fixture()
def mock_repo(monkeypatch) -> None:
    """
    Set testing data and variables to mock the cvelistV5 repository.
    """
    repo_path = f"{Path(cveorg_tests.__file__).resolve().parent}/cvelistV5"
    cve_path = r"CVE-(?:1999|2\d{3})-(?!0{4})(?:0\d{3}|[1-9]\d{3,}).json$"

    def clone_repo(self):
        return

    def update_repo(self):
        return

    def get_repo_changes(self):
        stdout = "CVE-2024-0181.json\nCVE-2024-0203.json\nCVE-2024-1087.json\nCVE-2024-4923.json\n"
        period_end = timezone.datetime(
            2024, 7, 1, tzinfo=timezone.get_current_timezone()
        )
        return stdout, period_end

    monkeypatch.setattr(CVEorgCollector, "REPO_PATH", repo_path)
    monkeypatch.setattr(CVEorgCollector, "CVE_PATH", cve_path)
    monkeypatch.setattr(CVEorgCollector, "clone_repo", clone_repo)
    monkeypatch.setattr(CVEorgCollector, "update_repo", update_repo)
    monkeypatch.setattr(CVEorgCollector, "get_repo_changes", get_repo_changes)


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
        test_api_v2_uri,
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
            f"{test_api_v2_uri}/flaws",
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

        access_method = client if not flaw.is_internal else auth_client()

        # 1.3) validate access control
        response = access_method.get(
            f"{test_api_v2_uri}/flaws/{flaw.uuid}?include_meta_attr=bz_id&include_history=true"
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

        # 3) create affects
        affects_data = []
        for stream in ps_update_streams:
            affects_data.append(
                {
                    "flaw": str(flaw.uuid),
                    "affectedness": "AFFECTED",
                    "resolution": "DELEGATED",
                    "ps_update_stream": stream.name,
                    "ps_component": ps_module.default_component,
                    "impact": "CRITICAL",
                    "embargoed": embargoed,
                }
            )
        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            affects_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200
        body = response.json()

        # 3.1) validate access control for affects
        response = access_method.get(f"{test_api_v2_uri}/flaws/{flaw.uuid}")
        assert response.status_code == expected_status
        if not embargoed:
            assert len(response.json()["affects"]) == ps_update_streams.count()

        # 4) get and validate trackers suggestions
        response = auth_client().post(
            f"{test_trackers_api_uri}/file",
            data={"flaw_uuids": [flaw.uuid]},
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        body = response.json()
        sorted_streams = sorted(
            stream["ps_update_stream"] for stream in body["streams_components"]
        )
        assert sorted_streams == sorted(stream.name for stream in ps_update_streams)
        assert (
            body["streams_components"][0]["ps_component"] == ps_module.default_component
        )

        suggested_trackers = [
            stream["ps_update_stream"] for stream in body["streams_components"]
        ]
        assert ps_update_streams[0].name in suggested_trackers

        # 5) create trackers
        for stream in ps_update_streams:
            affect = affect = Affect.objects.get(
                flaw=flaw, ps_update_stream=stream.name
            )
            tracker_data = {
                "affects": [affect.uuid],
                "embargoed": flaw.embargoed,
                "ps_update_stream": stream.name,
            }
            response = auth_client().post(
                f"{test_api_v2_uri}/trackers",
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
            JiraTrackerDownloadManager.link_tracker_with_affects(tracker_id)

        # 5.1) validate access control for trackers
        response = access_method.get(
            f"{test_api_v2_uri}/flaws/{flaw.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == expected_status
        if not embargoed:
            assert len(response.json()["trackers"]) == 2
            assert len(response.json()["affects"]) == 2
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
            f"{test_api_v2_uri}/flaws/{flaw.uuid}?include_meta_attr=bz_id&include_history=true"
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
                    f"{test_api_v2_uri}/flaws/{flaw.uuid}",
                    flaw_data,
                    format="json",
                    HTTP_BUGZILLA_API_KEY=bugzilla_token,
                    HTTP_JIRA_API_KEY=jira_token,
                )
                assert response.status_code == 200

        client_or_auth_client = client if not flaw.is_internal else auth_client()
        response = client_or_auth_client.get(
            f"{test_api_v2_uri}/flaws/{flaw.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 200
        body = response.json()
        assert len(body["trackers"]) == 2
        assert len(body["affects"]) == 2
        assert "curl" in body["components"]
        assert body["meta_attr"]["bz_id"]
        assert any(
            h["pgh_diff"] and "task_key" in h["pgh_diff"] for h in body["history"]
        )

    @pytest.mark.vcr
    @freeze_time(tzdatetime(2024, 8, 6))
    def test_cveorg_with_workflows(
        self,
        auth_client,
        bugzilla_token,
        client,
        enable_bz_async_sync,
        enable_jira_task_async_sync,
        enable_jira_tracker_sync,
        jira_token,
        mock_keywords,
        mock_repo,
        monkeypatch,
        test_api_uri,
    ):
        """
        Test that snippets and flaws are created correctly and can
        be edited and promoted until closed
        """
        # Simulates user behavior for task sync
        monkeypatch.setattr(JiraTaskmanQuerier, "is_service_account", lambda x: False)

        # 1) setup workflows for test
        workflow_framework = WorkflowFramework()
        workflow_framework._workflows = []

        state_new = {
            "name": WorkflowModel.WorkflowState.NEW,
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }

        state_triage = {
            "name": WorkflowModel.WorkflowState.TRIAGE,
            "requirements": ["has owner"],
            "jira_state": "Refinement",
            "jira_resolution": None,
        }

        state_sec = {
            "name": WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT,
            "requirements": ["has owner"],
            "jira_state": "In Progress",
            "jira_resolution": None,
        }

        state_done = {
            "name": WorkflowModel.WorkflowState.DONE,
            "requirements": [
                {
                    "condition": "OR",
                    "requirements": [
                        "has trackers",
                        "impact is low",
                        "impact is moderate",
                    ],
                }
            ],
            "jira_state": "Closed",
            "jira_resolution": "Done",
        }

        workflow = Workflow(
            {
                "name": "DEFAULT",
                "description": "random description",
                "priority": 1,
                "conditions": [],
                "states": [state_new, state_triage, state_sec, state_done],
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
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [state_reject],
            }
        )
        workflow_framework.register_workflow(workflow)
        workflow_framework.register_workflow(workflow_reject)

        # 2) collect well formated CVEs
        cc = CVEorgCollector()
        cc.snippet_creation_enabled = True
        cc.snippet_creation_start_date = None
        cc.collect()

        assert Snippet.objects.count() == 2
        assert Flaw.objects.count() == 2

        flaw1 = Flaw.objects.get(cve_id="CVE-2024-0181")
        flaw1._create_or_update_task(jira_token)
        snippet1 = Snippet.objects.get(external_id="CVE-2024-0181")
        assert flaw1
        assert snippet1
        assert snippet1.flaw == flaw1

        flaw2 = Flaw.objects.get(cve_id="CVE-2024-4923")
        flaw2._create_or_update_task(jira_token)
        snippet2 = Snippet.objects.get(external_id="CVE-2024-4923")
        assert flaw2
        assert snippet2
        assert snippet2.flaw == flaw2

        # 3) validate access control
        assert flaw1.is_internal
        response = client.get(
            f"{test_api_uri}/flaws/{flaw1.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 404
        response = auth_client().get(
            f"{test_api_uri}/flaws/{flaw1.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 200
        flaw1_body = response.json()

        assert flaw2.is_internal
        response = client.get(
            f"{test_api_uri}/flaws/{flaw2.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 404
        response = auth_client().get(
            f"{test_api_uri}/flaws/{flaw2.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 200
        flaw2_body = response.json()

        # 4) Test editing collected flaw
        flaw_data = {
            "title": "Spooky vulnerability",
            "comment_zero": flaw1_body["comment_zero"],
            "impact": "CRITICAL",
            "components": ["curl"],
            "source": "CVEORG",
            "owner": "concosta@redhat.com",
            "reported_dt": flaw1_body["reported_dt"],
            "unembargo_dt": flaw1_body["unembargo_dt"],
            "updated_dt": flaw1_body["updated_dt"],
            "embargoed": False,
        }
        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw1.uuid}",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200

        # 4.1) validate flaw still in NEW state
        response = auth_client().get(
            f"{test_api_uri}/flaws/{flaw1.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["classification"]["state"] == WorkflowModel.WorkflowState.NEW

        # 4.2) validate access control
        flaw1.refresh_from_db()
        flaw1._create_or_update_task(jira_token)
        assert flaw1.is_internal
        response = client.get(
            f"{test_api_uri}/flaws/{flaw1.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 404

        # 5) Validate workflow
        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw1.uuid}/promote",
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200
        flaw1.refresh_from_db()
        flaw1._create_or_update_task(jira_token)
        assert flaw1.workflow_state == WorkflowModel.WorkflowState.TRIAGE
        assert flaw1.is_internal

        # 5.1) validate flaw is promoted
        response = auth_client().get(
            f"{test_api_uri}/flaws/{flaw1.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["classification"]["state"] == WorkflowModel.WorkflowState.TRIAGE

        # 5.2) validate access control
        flaw1.refresh_from_db()
        flaw1._create_or_update_task(jira_token)
        assert flaw1.is_internal
        response = client.get(
            f"{test_api_uri}/flaws/{flaw1.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 404

        # 5.3) Validate promotion to secondary assessment
        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw1.uuid}/promote",
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200
        flaw1.refresh_from_db()
        flaw1._create_or_update_task(jira_token)
        assert flaw1.workflow_state == WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT

        # TODO remove this manual call after async task sync is calling it automatically
        flaw1.adjust_acls(save=False)
        flaw1.save(raise_validation_error=False)

        assert not flaw1.is_internal
        assert flaw1.is_public

        # 5.4) validate flaw is promoted and publicly accessible
        response = client.get(
            f"{test_api_uri}/flaws/{flaw1.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 200
        body = response.json()
        assert (
            body["classification"]["state"]
            == WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT
        )

        # 5.4) Validate promotion to done
        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw1.uuid}/promote",
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200
        flaw1.refresh_from_db()
        flaw1._create_or_update_task(jira_token)
        assert flaw1.workflow_state == WorkflowModel.WorkflowState.DONE
        assert not flaw1.is_internal
        assert flaw1.is_public

        response = client.get(
            f"{test_api_uri}/flaws/{flaw1.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["classification"]["state"] == WorkflowModel.WorkflowState.DONE

        # 6) Test editing rejected collected flaw
        flaw_data = {
            "title": "Not a vulnerability",
            "comment_zero": flaw2_body["comment_zero"],
            "impact": "LOW",
            "components": ["curl"],
            "source": "CVEORG",
            "reported_dt": flaw2_body["reported_dt"],
            "unembargo_dt": flaw2_body["unembargo_dt"],
            "updated_dt": flaw2_body["updated_dt"],
            "embargoed": False,
        }
        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw2.uuid}",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200
        flaw2.refresh_from_db()
        flaw2._create_or_update_task(jira_token)
        assert flaw2.is_internal

        # 6.1) Test rejecting collected flaw
        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw2.uuid}/reject",
            data={"reason": "This was a spam."},
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        body = response.json()
        assert response.status_code == 200
        assert body["classification"]["workflow"] == "REJECTED"
        assert body["classification"]["state"] == WorkflowModel.WorkflowState.REJECTED
        flaw2.refresh_from_db()
        flaw2._create_or_update_task(jira_token)
        assert flaw2.is_internal

        # 6.2) Test access control
        response = client.get(
            f"{test_api_uri}/flaws/{flaw2.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 404
        response = auth_client().get(
            f"{test_api_uri}/flaws/{flaw2.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["classification"]["state"] == WorkflowModel.WorkflowState.REJECTED

    @pytest.mark.vcr
    @freeze_time(tzdatetime(2024, 8, 6))
    def test_flaw_acl_values(
        self,
        auth_client,
        bugzilla_token,
        client,
        enable_bz_async_sync,
        enable_jira_task_async_sync,
        enable_jira_tracker_sync,
        jira_token,
        monkeypatch,
        test_api_uri,
    ):
        """
        Test that a flaw created via REST API has correct ACL values
        and that access control works properly based on these ACLs
        """
        # Simulates user behavior for task sync
        monkeypatch.setattr(JiraTaskmanQuerier, "is_service_account", lambda x: False)

        # 1) Create a flaw via REST API
        flaw_data = {
            "title": "Test ACL values",
            "comment_zero": "This is a test for ACL validation",
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

        # 1.1) Validate flaw was created successfully
        assert response.status_code == 201
        body = response.json()
        flaw_uuid = body["uuid"]

        # 1.2) Get the created flaw from database to check ACLs
        flaw = Flaw.objects.get(uuid=flaw_uuid)

        # 1.3) Verify ACL values are set correctly for public flaw
        assert not flaw.is_embargoed
        assert flaw.is_internal

        # Check that ACLs match expected public groups
        from django.conf import settings

        from osidb.core import generate_acls

        expected_read_acls = [
            uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_READ_GROUP])
        ]
        expected_write_acls = [
            uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_WRITE_GROUP])
        ]

        assert flaw.acl_read == expected_read_acls
        assert flaw.acl_write == expected_write_acls

        # 2) Create an embargoed flaw via REST API
        embargoed_flaw_data = {
            "title": "Test Embargoed ACL values",
            "comment_zero": "This is a test for embargoed ACL validation",
            "impact": "CRITICAL",
            "components": ["kernel"],
            "source": "REDHAT",
            "reported_dt": "2024-08-06T00:00:00.000Z",
            "unembargo_dt": "2024-08-07T00:00:00.000Z",
            "embargoed": True,
        }

        response = auth_client().post(
            f"{test_api_uri}/flaws",
            embargoed_flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        # 2.1) Validate embargoed flaw was created successfully
        assert response.status_code == 201
        embargoed_body = response.json()
        embargoed_flaw_uuid = embargoed_body["uuid"]

        # 2.2) Get the created embargoed flaw from database to check ACLs
        embargoed_flaw = Flaw.objects.get(uuid=embargoed_flaw_uuid)

        # 2.3) Verify ACL values are set correctly for embargoed flaw
        assert embargoed_flaw.is_embargoed
        assert not embargoed_flaw.is_public
        assert not embargoed_flaw.is_internal

        # Check that ACLs match expected embargoed groups
        expected_embargoed_read_acls = [
            uuid.UUID(acl) for acl in generate_acls([settings.EMBARGO_READ_GROUP])
        ]
        expected_embargoed_write_acls = [
            uuid.UUID(acl) for acl in generate_acls([settings.EMBARGO_WRITE_GROUP])
        ]

        assert embargoed_flaw.acl_read == expected_embargoed_read_acls
        assert embargoed_flaw.acl_write == expected_embargoed_write_acls

        # 3) Test access control based on ACLs
        # 3.1) Internal flaw should be inaccessible to unauthenticated client
        response = client.get(f"{test_api_uri}/flaws/{flaw_uuid}")
        assert response.status_code == 404

        # 3.2) Embargoed flaw should NOT be accessible to unauthenticated client
        response = client.get(f"{test_api_uri}/flaws/{embargoed_flaw_uuid}")
        assert response.status_code == 404

        # 3.3) Authenticated client should be able to access both flaws
        response = auth_client().get(f"{test_api_uri}/flaws/{flaw_uuid}")
        assert response.status_code == 200

        response = auth_client().get(f"{test_api_uri}/flaws/{embargoed_flaw_uuid}")

        assert response.status_code == 200
