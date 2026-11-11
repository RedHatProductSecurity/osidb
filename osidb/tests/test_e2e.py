import uuid
from pathlib import Path
from unittest.mock import Mock

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone
from freezegun import freeze_time

from apps.taskman.service import JiraTaskmanQuerier
from apps.trackers.constants import TRACKERS_API_VERSION
from apps.workflows.models import Workflow
from apps.workflows.workflow import WorkflowFramework
from collectors.bzimport.collectors import BugzillaTrackerCollector
from collectors.cveorg import tests as cveorg_tests
from collectors.cveorg.collectors import CVEorgCollector
from collectors.cveorg.models import Keyword
from collectors.jiraffe.collectors import (
    JiraTrackerCollector,
    JiraTrackerDownloadManager,
)
from osidb.core import set_user_acls
from osidb.models import Affect, Flaw, Impact, Profile, PsUpdateStream, Snippet, Tracker
from osidb.sync_manager import (
    BZSyncManager,
    BZTrackerDownloadManager,
    JiraTaskSyncManager,
    JiraTaskTransitionManager,
)
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    default_rpm_purl_for_ps_component,
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
        jira_email,
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
            HTTP_JIRA_API_EMAIL=jira_email,
            HTTP_JIRA_API_KEY=jira_token,
        )

        # 1.1) validade flaw was created and bz sync is scheduled
        assert response.status_code == 201
        body = response.json()
        assert BZSyncManager.objects.get(
            name=BZSyncManager.__name__, sync_id=body["uuid"]
        )
        assert JiraTaskSyncManager.objects.get(
            name=JiraTaskSyncManager.__name__, sync_id=body["uuid"]
        )

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
            assert response.json()["bz_id"]

        # 2) get valid external data
        ps_update_streams = PsUpdateStream.objects.filter(
            active_to_ps_module__bts_name="jboss"
        ).order_by("name")[:2]
        ps_module = ps_update_streams[0].active_to_ps_module
        ps_module.private_trackers_allowed = True
        ps_module.save()

        # 3) create affects
        affects_data = []
        comp = ps_module.default_component
        purl = default_rpm_purl_for_ps_component(comp)
        for stream in ps_update_streams:
            affects_data.append(
                {
                    "flaw": str(flaw.uuid),
                    "affectedness": "AFFECTED",
                    "resolution": "DELEGATED",
                    "ps_update_stream": stream.name,
                    "ps_component": comp,
                    "purl": purl,
                    "impact": "CRITICAL",
                    "embargoed": embargoed,
                }
            )
        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            affects_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_EMAIL=jira_email,
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
            affect = Affect.objects.get(flaw=flaw, ps_update_stream=stream.name)
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
                HTTP_JIRA_API_EMAIL=jira_email,
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
            assert response.json()["bz_id"]

        # 6) validate users can promote flaws
        # 6.1) setup workflows for test
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

        # 6.2) reclassify flaw — classification is automatic based on data
        # restore ACLs after unauthenticated API calls which reset them via middleware
        set_user_acls(settings.ALL_GROUPS)
        flaw.refresh_from_db()
        flaw.adjust_classification()
        flaw.save()

        # 6.3) validate classification was applied
        response = auth_client().get(
            f"{test_api_v2_uri}/flaws/{flaw.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["classification"]["state"] == "SECONDARY_ASSESSMENT"

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
                    HTTP_JIRA_API_EMAIL=jira_email,
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
        assert body["bz_id"]
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
        jira_email,
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
            "name": "NEW",
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }

        state_triage = {
            "name": "TRIAGE",
            "requirements": ["has owner"],
            "jira_state": "Refinement",
            "jira_resolution": None,
        }

        state_sec = {
            "name": "SECONDARY_ASSESSMENT",
            "requirements": ["has owner"],
            "jira_state": "In Progress",
            "jira_resolution": None,
            "visibility": "PUBLIC",
        }

        state_done = {
            "name": "DONE",
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
                "priority": 0,
                "conditions": [],
                "states": [state_new, state_triage, state_sec, state_done],
            }
        )

        state_reject = {
            "name": "DONE",
            "requirements": [],
            "jira_state": "Closed",
            "jira_resolution": "Won't Do",
        }
        workflow_reject = Workflow(
            {
                "name": "REJECTED",
                "description": "random description",
                "priority": 1,
                "conditions": ["has label rejected"],
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
        user = User.objects.create(username="concosta")
        Profile.objects.create(user=user, atlassian_cloud_id="test-cloud-id")
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
            HTTP_JIRA_API_EMAIL=jira_email,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200

        # 4.1) validate flaw still in NEW state
        response = auth_client().get(
            f"{test_api_uri}/flaws/{flaw1.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["classification"]["state"] == "NEW"

        # 4.2) validate access control
        flaw1.refresh_from_db()
        flaw1._create_or_update_task(jira_token)
        assert flaw1.is_internal
        response = client.get(
            f"{test_api_uri}/flaws/{flaw1.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 404

        # 5) Validate auto-classification and visibility auto-adjustment
        # restore ACLs after unauthenticated API calls which reset them via middleware
        set_user_acls(settings.ALL_GROUPS)
        flaw1.refresh_from_db()
        flaw1.adjust_classification()
        flaw1.save()
        flaw1._create_or_update_task(jira_token)
        assert flaw1.workflow_state == "DONE"

        # visibility is auto-adjusted to PUBLIC during classification
        # because SECONDARY_ASSESSMENT defines visibility: PUBLIC
        assert not flaw1.is_internal
        assert flaw1.is_public

        # 5.1) validate classification and public access via API
        response = client.get(
            f"{test_api_uri}/flaws/{flaw1.uuid}?include_meta_attr=bz_id&include_history=true"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["classification"]["state"] == "DONE"

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
            HTTP_JIRA_API_EMAIL=jira_email,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200
        flaw2.refresh_from_db()
        flaw2._create_or_update_task(jira_token)
        assert flaw2.is_internal

        # 6.1) Test rejecting collected flaw via rejected workflow label
        from osidb.models import WorkflowLabel

        WorkflowLabel.objects.create(flaw=flaw2, name="rejected")
        flaw2.adjust_classification()
        flaw2.save(raise_validation_error=False)
        flaw2._create_or_update_task(jira_token)
        assert flaw2.workflow_name == "REJECTED"
        assert flaw2.workflow_state == "DONE"
        assert flaw2.is_internal

        # 6.1.1) Verify rejected flaw stays internal after save
        flaw2.save(raise_validation_error=False)
        assert flaw2.is_internal, (
            "Rejected flaws should stay internal even in DONE state"
        )

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
        assert body["classification"]["state"] == "DONE"
        assert body["classification"]["workflow"] == "REJECTED"

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
        jira_email,
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
            HTTP_JIRA_API_EMAIL=jira_email,
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
            uuid.UUID(acl) for acl in generate_acls(settings.INTERNAL_READ_GROUPS)
        ]
        expected_write_acls = [
            uuid.UUID(acl) for acl in generate_acls(settings.INTERNAL_WRITE_GROUPS)
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
            HTTP_JIRA_API_EMAIL=jira_email,
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
            uuid.UUID(acl) for acl in generate_acls(settings.EMBARGO_READ_GROUPS)
        ]
        expected_embargoed_write_acls = [
            uuid.UUID(acl) for acl in generate_acls(settings.EMBARGO_WRITE_GROUPS)
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


class TestE2ETrackerRelink:
    """
    E2E regression tests for OSIDB-5840: flaw reclassification after the
    affect-tracker relink done by the tracker download managers.

    Production incident (CVE-2026-61674): a tracker filed directly in Jira
    was synced in by the collector and relinked to the last affect that
    was still missing its tracker, but the plain bulk link updates fired
    no save signals, nothing re-saved the flaw and it stalled in
    PRE_SECONDARY_ASSESSMENT for ~2.5 days until an unrelated BU-label
    edit re-saved it.

    These tests drive the real chain - REST API, Bugzilla/Jira task sync,
    collector, download manager - under the real workflow definitions and
    let the tracker sync itself do the promoting: no explicit flaw save or
    adjust_classification call anywhere. The trackers are filed directly
    in the external system (replayed from cassettes), never through the
    OSIDB tracker API - the API filing path pre-links the affect via
    affect.save() and is not affected by the bug.

    The taskman transition is asserted with a mocked
    JiraTaskTransitionManager.schedule executed from the captured
    transaction.on_commit callbacks - no Jira I/O for it.
    """

    @pytest.fixture(autouse=True)
    def real_workflow_definitions(self):
        """
        the TestE2E tests above swap the workflow framework singleton for
        toy workflow definitions - drop whatever is loaded so the real
        definitions from apps/workflows/workflows are lazily reloaded
        """
        WorkflowFramework()._workflows = []
        yield

    def _create_flaw_with_task(
        self,
        auth_client,
        bugzilla_token,
        jira_email,
        jira_token,
        test_api_v2_uri,
        embargoed=False,
    ):
        """
        create a flaw over the REST API and let it go through the real
        Bugzilla and taskman sync, ending with a taskman task (task_key)
        and a TRIAGE classification under the real workflows
        """
        response = auth_client().post(
            f"{test_api_v2_uri}/flaws",
            {
                "title": "test validations",
                "comment_zero": "this is a simple test",
                # a critical impact would route the flaw into the MANUAL
                # workflow - keep it in the DEFAULT one like the plan asks
                "impact": "MODERATE",
                "components": ["curl"],
                "source": "REDHAT",
                "reported_dt": "2024-08-06T00:00:00.000Z",
                "unembargo_dt": (
                    "2024-08-07T00:00:00.000Z"
                    if embargoed
                    else "2024-08-06T00:00:00.000Z"
                ),
                "embargoed": embargoed,
                # satisfy the TRIAGE requirements of the real workflows
                "cwe_id": "CWE-79",
                "cve_description": "a cve description",
            },
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_EMAIL=jira_email,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 201
        flaw = Flaw.objects.get(uuid=response.json()["uuid"])

        # synchronously perform the scheduled async syncs
        flaw._perform_bzsync(bz_api_key=bugzilla_token)
        flaw._create_or_update_task(jira_token)
        return flaw

    def _create_affects(
        self,
        auth_client,
        bugzilla_token,
        jira_email,
        jira_token,
        test_api_v2_uri,
        flaw,
        embargoed=False,
        count=1,
    ):
        """
        create resolved AFFECTED:DELEGATED affects over the REST API on
        the first <count> Jira-BTS update streams, returning the streams
        """
        ps_update_streams = PsUpdateStream.objects.filter(
            active_to_ps_module__bts_name="jboss"
        ).order_by("name")[:count]
        comp = ps_update_streams[0].active_to_ps_module.default_component
        purl = default_rpm_purl_for_ps_component(comp)
        affects_data = [
            {
                "flaw": str(flaw.uuid),
                "affectedness": "AFFECTED",
                "resolution": "DELEGATED",
                "ps_update_stream": stream.name,
                "ps_component": comp,
                "purl": purl,
                "impact": "MODERATE",
                "embargoed": embargoed,
            }
            for stream in ps_update_streams
        ]
        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            affects_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_EMAIL=jira_email,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200
        return ps_update_streams

    def _mock_taskman_transition(self, monkeypatch):
        """
        enable the taskman auto-sync gate for the relink reclassification
        and switch taskman to its asynchronous mode so that the transition
        scheduling can be asserted without any Jira I/O
        """
        monkeypatch.setattr("apps.taskman.constants.JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
        monkeypatch.setattr(
            "osidb.models.flaw.flaw.JIRA_TASKMAN_ASYNCHRONOUS_SYNC", True
        )
        transition_schedule = Mock()
        monkeypatch.setattr(JiraTaskTransitionManager, "schedule", transition_schedule)
        sync_schedule = Mock()
        monkeypatch.setattr(JiraTaskSyncManager, "schedule", sync_schedule)
        return transition_schedule, sync_schedule

    @pytest.mark.enable_signals
    @pytest.mark.vcr
    @freeze_time(tzdatetime(2024, 8, 6))
    def test_collector_filed_tracker_promotes_flaw(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_async_sync,
        enable_jira_task_async_sync,
        jira_email,
        jira_token,
        monkeypatch,
        setup_sample_external_resources,
        test_api_v2_uri,
        django_capture_on_commit_callbacks,
    ):
        """
        a flaw with a taskman task and a resolved affect sits in
        PRE_SECONDARY_ASSESSMENT; a tracker filed directly in Jira is
        synced in by the collector and the link alone must promote the
        flaw to DONE with a single taskman task transition scheduled on
        commit - the exact chain that stalled in production until an
        unrelated edit re-saved the flaw (OSIDB-5840)
        """
        monkeypatch.setattr(JiraTaskmanQuerier, "is_service_account", lambda x: False)

        flaw = self._create_flaw_with_task(
            auth_client,
            bugzilla_token,
            jira_email,
            jira_token,
            test_api_v2_uri,
        )
        self._create_affects(
            auth_client,
            bugzilla_token,
            jira_email,
            jira_token,
            test_api_v2_uri,
            flaw,
            count=1,
        )
        flaw.refresh_from_db()
        assert flaw.workflow_name == "DEFAULT"
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"
        assert flaw.resolved_dt is None
        affect = flaw.affects.get()
        assert affect.tracker is None

        # the tracker was filed directly in Jira - the collector is the
        # first OSIDB component to see it
        JiraTrackerCollector().collect("RHEL-59830")
        updated_dt = flaw.updated_dt

        transition_schedule, sync_schedule = self._mock_taskman_transition(monkeypatch)
        with django_capture_on_commit_callbacks(execute=False) as callbacks:
            JiraTrackerDownloadManager.link_tracker_with_affects("RHEL-59830")
            # nothing may touch Jira before the transaction commits
            assert not transition_schedule.called

        # exactly one taskman job: a task transition, not a full task re-sync
        assert len(callbacks) == 1
        callbacks[0]()  # simulate the commit
        transition_schedule.assert_called_once_with(str(flaw.uuid))
        assert not sync_schedule.called

        flaw.refresh_from_db()
        # all affects resolved and tracked, and DONE has no requirements
        assert flaw.workflow_state == "DONE"
        assert flaw.resolved_dt is not None
        # the mid-air collision timestamp must not move
        assert flaw.updated_dt == updated_dt
        affect.refresh_from_db()
        assert affect.tracker.external_system_id == "RHEL-59830"

    @pytest.mark.enable_signals
    @pytest.mark.vcr
    @freeze_time(tzdatetime(2024, 8, 6))
    def test_tracker_sync_task_promotes_flaw(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_async_sync,
        enable_jira_task_async_sync,
        jira_email,
        jira_token,
        monkeypatch,
        setup_sample_external_resources,
        test_api_v2_uri,
    ):
        """
        the full tracker download task path: the collector schedules the
        download, sync_task runs the whole chain (fetch, convert, save,
        link, reclassify) and ends up finished with the flaw promoted -
        the promotion must not depend on anything else saving the flaw
        afterwards (OSIDB-5840)
        """
        monkeypatch.setattr(JiraTaskmanQuerier, "is_service_account", lambda x: False)

        flaw = self._create_flaw_with_task(
            auth_client,
            bugzilla_token,
            jira_email,
            jira_token,
            test_api_v2_uri,
        )
        self._create_affects(
            auth_client,
            bugzilla_token,
            jira_email,
            jira_token,
            test_api_v2_uri,
            flaw,
            count=1,
        )
        flaw.refresh_from_db()
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

        # production entry: the collector schedules the download task,
        # the worker runs it over the whole chain
        JiraTrackerDownloadManager.schedule("RHEL-59830")
        JiraTrackerDownloadManager.sync_task("RHEL-59830")

        manager = JiraTrackerDownloadManager.objects.get(
            name=JiraTrackerDownloadManager.__name__, sync_id="RHEL-59830"
        )
        assert manager.last_finished_dt is not None
        assert manager.last_failed_dt is None
        assert manager.permanently_failed is False

        flaw.refresh_from_db()
        assert flaw.workflow_state == "DONE"
        assert flaw.resolved_dt is not None
        affect = flaw.affects.get()
        assert affect.tracker.external_system_id == "RHEL-59830"

    @pytest.mark.enable_signals
    @pytest.mark.vcr
    def test_bz_collector_filed_tracker_promotes_flaw(
        self, monkeypatch, django_capture_on_commit_callbacks
    ):
        """
        the Bugzilla variant of the collector-filed promotion: a BZ
        tracker created against the flaw is synced in by the Bugzilla
        collector and the link promotes the flaw; the promotion must be
        attributed to the tracker sync in the flaw audit trail
        (OSIDB-5840)
        """
        ps_module = PsModuleFactory(bts_name="bugzilla", name="epel-all")
        ps_update_stream = PsUpdateStreamFactory(name="epel-all", ps_module=ps_module)
        flaw = FlawFactory(
            bz_id="1629662",  # the flaw bug the recorded tracker blocks
            embargoed=False,
            task_key="TASK-5840-BZ",
            impact=Impact.MODERATE,
            cwe_id="CWE-79",
            cve_description="a cve description",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="jhead",  # the recorded tracker's component
        )
        flaw.refresh_from_db()
        assert flaw.workflow_name == "DEFAULT"
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"
        assert affect.tracker is None

        # the tracker was filed directly in Bugzilla - the collector is
        # the first OSIDB component to see it
        BugzillaTrackerCollector().sync_tracker("1629664")

        transition_schedule, _ = self._mock_taskman_transition(monkeypatch)
        with django_capture_on_commit_callbacks(execute=False) as callbacks:
            BZTrackerDownloadManager.link_tracker_with_affects("1629664")
            assert not transition_schedule.called
        assert len(callbacks) == 1
        callbacks[0]()  # simulate the commit
        transition_schedule.assert_called_once_with(str(flaw.uuid))

        flaw.refresh_from_db()
        assert flaw.workflow_state == "DONE"
        assert flaw.resolved_dt is not None
        affect.refresh_from_db()
        assert affect.tracker.external_system_id == "1629664"

        # the promotion is attributed to the tracker sync in the audit trail
        event = (
            Flaw.pgh_event_model.objects.filter(
                pgh_obj_id=flaw.uuid, workflow_state="DONE"
            )
            .order_by("-pgh_created_at")
            .first()
        )
        assert event is not None
        assert event.pgh_context.metadata["action"] == "link_tracker_with_affects"
        assert event.pgh_context.metadata["source"] == "celery"

    @pytest.mark.enable_signals
    @pytest.mark.vcr
    @freeze_time(tzdatetime(2024, 8, 6))
    def test_collector_filed_tracker_promotes_embargoed_flaw(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_async_sync,
        enable_jira_task_async_sync,
        jira_email,
        jira_token,
        monkeypatch,
        setup_sample_external_resources,
        test_api_v2_uri,
    ):
        """
        the same promotion chain for an embargoed flaw under the real
        EMBARGOED workflow: linking the last tracker advances the flaw to
        SECONDARY_ASSESSMENT (DONE stays gated behind the unembargo)
        (OSIDB-5840)
        """
        monkeypatch.setattr(JiraTaskmanQuerier, "is_service_account", lambda x: False)

        flaw = self._create_flaw_with_task(
            auth_client,
            bugzilla_token,
            jira_email,
            jira_token,
            test_api_v2_uri,
            embargoed=True,
        )
        self._create_affects(
            auth_client,
            bugzilla_token,
            jira_email,
            jira_token,
            test_api_v2_uri,
            flaw,
            embargoed=True,
            count=1,
        )
        flaw.refresh_from_db()
        assert flaw.workflow_name == "EMBARGOED"
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

        # an embargoed tracker was filed directly in Jira
        JiraTrackerCollector().collect("RHEL-59828")
        JiraTrackerDownloadManager.link_tracker_with_affects("RHEL-59828")

        flaw.refresh_from_db()
        assert flaw.workflow_name == "EMBARGOED"
        assert flaw.workflow_state == "SECONDARY_ASSESSMENT"
        # DONE requires the unembargo, so no resolution stamp yet
        assert flaw.resolved_dt is None
        affect = flaw.affects.get()
        assert affect.tracker.external_system_id == "RHEL-59828"

    @pytest.mark.enable_signals
    @pytest.mark.vcr
    @freeze_time(tzdatetime(2024, 8, 6))
    def test_last_collector_filed_tracker_triggers_single_promotion(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_async_sync,
        enable_jira_task_async_sync,
        jira_email,
        jira_token,
        monkeypatch,
        setup_sample_external_resources,
        test_api_v2_uri,
        django_capture_on_commit_callbacks,
    ):
        """
        the production scenario of the incident: two affects still
        missing their trackers, two trackers filed and synced
        sequentially - the first link leaves the flaw untouched in
        PRE_SECONDARY_ASSESSMENT with no taskman job, only the last link
        promotes it and schedules exactly one task transition
        (OSIDB-5840)
        """
        monkeypatch.setattr(JiraTaskmanQuerier, "is_service_account", lambda x: False)

        flaw = self._create_flaw_with_task(
            auth_client,
            bugzilla_token,
            jira_email,
            jira_token,
            test_api_v2_uri,
        )
        streams = self._create_affects(
            auth_client,
            bugzilla_token,
            jira_email,
            jira_token,
            test_api_v2_uri,
            flaw,
            count=2,
        )
        flaw.refresh_from_db()
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"
        affects = {
            stream.name: flaw.affects.get(ps_update_stream=stream.name)
            for stream in streams
        }

        jc = JiraTrackerCollector()
        transition_schedule, _ = self._mock_taskman_transition(monkeypatch)
        with django_capture_on_commit_callbacks(execute=False) as callbacks:
            # the first link does not change the classification: the
            # second affect is still untracked
            jc.collect("RHEL-59830")
            JiraTrackerDownloadManager.link_tracker_with_affects("RHEL-59830")
            affects["rhel-8"].refresh_from_db()
            assert affects["rhel-8"].tracker.external_system_id == "RHEL-59830"
            flaw.refresh_from_db()
            assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"
            assert not transition_schedule.called

            # the last link promotes the flaw
            jc.collect("RHEL-59831")
            JiraTrackerDownloadManager.link_tracker_with_affects("RHEL-59831")

        assert len(callbacks) == 1
        callbacks[0]()  # simulate the commit
        transition_schedule.assert_called_once_with(str(flaw.uuid))

        flaw.refresh_from_db()
        assert flaw.workflow_state == "DONE"
        assert flaw.resolved_dt is not None
        affects["rhel-8.10.z"].refresh_from_db()
        assert affects["rhel-8.10.z"].tracker.external_system_id == "RHEL-59831"

    @pytest.mark.enable_signals
    @pytest.mark.vcr
    @freeze_time(tzdatetime(2024, 8, 6))
    def test_external_tracker_unlink_regresses_flaw(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_async_sync,
        enable_jira_task_async_sync,
        jira_email,
        jira_token,
        monkeypatch,
        setup_sample_external_resources,
        test_api_v2_uri,
    ):
        """
        the regression direction through the whole chain: the external
        tracker stops referencing the flaw, the next collector sync sees
        the change, the reconciliation unlinks the affect and the flaw
        must regress from DONE back to PRE_SECONDARY_ASSESSMENT with its
        resolution stamp cleared (OSIDB-5840)
        """
        monkeypatch.setattr(JiraTaskmanQuerier, "is_service_account", lambda x: False)

        flaw = self._create_flaw_with_task(
            auth_client,
            bugzilla_token,
            jira_email,
            jira_token,
            test_api_v2_uri,
        )
        self._create_affects(
            auth_client,
            bugzilla_token,
            jira_email,
            jira_token,
            test_api_v2_uri,
            flaw,
            count=1,
        )
        flaw.refresh_from_db()
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

        # the tracker is filed, synced in and the flaw promotes to DONE
        jc = JiraTrackerCollector()
        jc.collect("RHEL-59830")
        JiraTrackerDownloadManager.link_tracker_with_affects("RHEL-59830")
        flaw.refresh_from_db()
        assert flaw.workflow_state == "DONE"
        assert flaw.resolved_dt is not None

        # the external tracker no longer references the flaw - the next
        # sync reconciles the link away
        jc.collect("RHEL-59830")
        JiraTrackerDownloadManager.link_tracker_with_affects("RHEL-59830")

        flaw.refresh_from_db()
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"
        assert flaw.resolved_dt is None
        affect = flaw.affects.get()
        affect.refresh_from_db()
        assert affect.tracker is None

    @pytest.mark.enable_signals
    @pytest.mark.vcr
    @freeze_time(tzdatetime(2024, 8, 6))
    def test_taskman_failure_does_not_fail_tracker_sync(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_async_sync,
        enable_jira_task_async_sync,
        jira_email,
        jira_token,
        monkeypatch,
        setup_sample_external_resources,
        test_api_v2_uri,
        django_capture_on_commit_callbacks,
    ):
        """
        a failing taskman transition runs in a robust commit hook: the
        already committed link and classification change must survive and
        the tracker sync itself must complete - a retry of a failed sync
        would see no link change anymore, so the transition would never
        be re-scheduled (OSIDB-5840)
        """
        monkeypatch.setattr(JiraTaskmanQuerier, "is_service_account", lambda x: False)

        flaw = self._create_flaw_with_task(
            auth_client,
            bugzilla_token,
            jira_email,
            jira_token,
            test_api_v2_uri,
        )
        self._create_affects(
            auth_client,
            bugzilla_token,
            jira_email,
            jira_token,
            test_api_v2_uri,
            flaw,
            count=1,
        )
        flaw.refresh_from_db()
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

        JiraTrackerCollector().collect("RHEL-59830")

        monkeypatch.setattr("apps.taskman.constants.JIRA_TASKMAN_AUTO_SYNC_FLAW", True)

        def broken_tasksync(*args, **kwargs):
            raise RuntimeError("taskman is down")

        monkeypatch.setattr(Flaw, "tasksync", broken_tasksync)

        # the commit hook fails, yet the tracker sync itself must succeed
        with django_capture_on_commit_callbacks(execute=True):
            JiraTrackerDownloadManager.link_tracker_with_affects("RHEL-59830")

        # the committed classification and link survive the taskman failure
        flaw.refresh_from_db()
        assert flaw.workflow_state == "DONE"
        affect = flaw.affects.get()
        affect.refresh_from_db()
        assert affect.tracker.external_system_id == "RHEL-59830"
