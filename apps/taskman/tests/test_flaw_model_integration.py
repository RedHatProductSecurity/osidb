from datetime import datetime

import pytest
from django.utils.timezone import make_aware
from jira.exceptions import JIRAError
from rest_framework.response import Response

import apps.taskman.mixins as mixins
import osidb.models.flaw.flaw as flaw_module
import osidb.serializer as serializer
from apps.taskman.exceptions import TaskWritePermissionsException
from apps.taskman.service import JiraTaskmanQuerier
from osidb.models import Flaw, FlawSource, Impact
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


def mock_get_task_existing(self, flaw_uuid: str):
    return Response(data=None, status=200)


def mock_get_task_missing(self, flaw_uuid: str):
    return Response(data=None, status=404)


class TestFlawModelIntegration(object):
    def test_tasksync(self, monkeypatch, user_token):
        """ """
        sync_count = 0

        def mock_create_or_update_task(self, flaw):
            nonlocal sync_count
            sync_count += 1
            return Response(
                data={
                    "key": "TASK-123",
                    "fields": {
                        "status": {"name": "New"},
                        "resolution": None,
                        "updated": "2024-06-25T21:20:43.988+0000",
                    },
                },
                status=200,
            )

        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", mock_create_or_update_task
        )
        monkeypatch.setattr(flaw_module, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)

        flaw1 = FlawFactory(cve_id="CVE-2020-8002")
        AffectFactory(flaw=flaw1)
        flaw1.task_key = "TASK-123"
        flaw1.save()

        # no important changes requires no syncing
        assert flaw1.tasksync(jira_token=user_token) is None
        assert sync_count == 0

        flaw1.cve_id = "CVE-2020-8003"
        assert flaw1.tasksync(jira_token=user_token) is None
        assert sync_count == 1

        flaw2 = FlawFactory(cve_id="CVE-2020-8004")
        AffectFactory(flaw=flaw2)
        flaw2.cve_id = "CVE-2020-8005"
        assert flaw2.tasksync(jira_token=user_token) is None
        # flaws without task_key were created by collectors should not sync in jira
        assert sync_count == 1

    def test_syncing(self, monkeypatch, acl_read, acl_write, user_token):
        sync_count = 0

        def mock_create_or_update_task(self, flaw):
            nonlocal sync_count
            sync_count += 1
            return Response(
                data={
                    "key": "TASK-123",
                    "fields": {
                        "status": {"name": "New"},
                        "resolution": None,
                        "updated": "2024-06-25T21:20:43.988+0000",
                    },
                },
                status=200,
            )

        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", mock_create_or_update_task
        )

        monkeypatch.setattr(flaw_module, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
        monkeypatch.setattr(mixins, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)

        flaw = Flaw(
            cve_id="CVE-2020-8004",
            title="CVE-2020-8004 kernel: some description",
            acl_read=acl_read,
            acl_write=acl_write,
            comment_zero="Comment zero",
            components=["component"],
            impact=Impact.LOW,
            source=FlawSource.INTERNET,
            unembargo_dt=make_aware(datetime.now()),
            reported_dt=make_aware(datetime.now()),
            created_dt=make_aware(datetime.now()),
            updated_dt=make_aware(datetime.now()),
        )
        assert flaw.save(jira_token=user_token) is None
        assert sync_count == 1

        AffectFactory(flaw=flaw)

        # save without token should not sync
        assert flaw.save() is None
        assert sync_count == 1

    def test_create_api(
        self, monkeypatch, auth_client, test_osidb_api_uri, bz_api_key, user_token
    ):
        sync_count = 0

        def mock_create_or_update_task(self, flaw):
            nonlocal sync_count
            sync_count += 1
            return Response(
                data={
                    "key": "TASK-123",
                    "fields": {
                        "status": {"name": "New"},
                        "resolution": None,
                        "updated": "2024-06-25T21:20:43.988+0000",
                    },
                },
                status=200,
            )

        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", mock_create_or_update_task
        )
        monkeypatch.setattr(flaw_module, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
        monkeypatch.setattr(serializer, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)

        flaw_data = {
            "cwe_id": "CWE-1",
            "title": "Foo",
            "impact": "CRITICAL",
            "components": ["curl"],
            "source": "INTERNET",
            "comment_zero": "test",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "embargoed": False,
        }
        response = auth_client().post(
            f"{test_osidb_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bz_api_key,
            HTTP_JIRA_API_KEY=user_token,
        )
        assert response.status_code == 201
        assert sync_count == 1

    def test_update_api(
        self, monkeypatch, auth_client, test_osidb_api_uri, bz_api_key, user_token
    ):
        sync_count = 0

        def mock_create_or_update_task(self, flaw):
            nonlocal sync_count
            sync_count += 1
            return Response(
                data={
                    "key": "TASK-123",
                    "fields": {
                        "status": {"name": "New"},
                        "resolution": None,
                        "updated": "2024-06-25T21:20:43.988+0000",
                    },
                },
                status=200,
            )

        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", mock_create_or_update_task
        )

        monkeypatch.setattr(flaw_module, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
        monkeypatch.setattr(serializer, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)

        flaw = FlawFactory(embargoed=False, impact=Impact.IMPORTANT)
        AffectFactory(flaw=flaw)
        flaw.task_key = "TASK-123"
        flaw.save()
        response = auth_client().get(f"{test_osidb_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200

        response = auth_client().put(
            f"{test_osidb_api_uri}/flaws/{flaw.uuid}",
            {
                "uuid": flaw.uuid,
                "cve_id": flaw.cve_id,
                "title": f"{flaw.title} appended test title",
                "comment_zero": flaw.comment_zero,
                "impact": Impact.IMPORTANT,
                "source": flaw.source,
                "embargoed": False,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY=bz_api_key,
            HTTP_JIRA_API_KEY=user_token,
        )
        # no important changes requires no syncing
        assert response.status_code == 200
        assert sync_count == 0

        flaw = Flaw.objects.get(uuid=flaw.uuid)
        response = auth_client().put(
            f"{test_osidb_api_uri}/flaws/{flaw.uuid}",
            {
                "uuid": flaw.uuid,
                "cve_id": flaw.cve_id,
                "title": f"{flaw.title} appended test title",
                "comment_zero": flaw.comment_zero,
                "impact": Impact.LOW,
                "source": flaw.source,
                "embargoed": False,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY=bz_api_key,
            HTTP_JIRA_API_KEY=user_token,
        )
        assert response.status_code == 200
        assert sync_count == 1

    def test_create_jira_task_param(
        self, monkeypatch, auth_client, test_osidb_api_uri, bz_api_key, user_token
    ):
        def mock_create_or_update_task(self, flaw):
            flaw.task_key = "TASK-123"
            return Response(
                data={
                    "key": "TASK-123",
                    "fields": {
                        "status": {"name": "New"},
                        "resolution": None,
                        "updated": "2024-06-25T21:20:43.988+0000",
                    },
                },
                status=200,
            )

        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", mock_create_or_update_task
        )

        monkeypatch.setattr(flaw_module, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
        monkeypatch.setattr(serializer, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)
        flaw.task_key = ""
        flaw.save()

        # Update flaw with no task without using the create_jira_task param:
        # it should not create any task
        response = auth_client().put(
            f"{test_osidb_api_uri}/flaws/{flaw.uuid}",
            {
                "uuid": flaw.uuid,
                "cve_id": flaw.cve_id,
                "title": f"{flaw.title} appended test title",
                "comment_zero": flaw.comment_zero,
                "impact": flaw.impact,
                "source": flaw.source,
                "embargoed": False,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY=bz_api_key,
            HTTP_JIRA_API_KEY=user_token,
        )
        assert response.status_code == 200
        assert not flaw.task_key

        # Update flaw with failing validations:
        # it should not create any task
        flaw = Flaw.objects.get(uuid=flaw.uuid)
        response = auth_client().put(
            f"{test_osidb_api_uri}/flaws/{flaw.uuid}",
            {
                "uuid": flaw.uuid,
                "cve_id": flaw.cve_id,
                "title": f"{flaw.title} appended test title",
                "comment_zero": flaw.comment_zero,
                "impact": flaw.impact,
                "source": "",  # empty source should fail validations
                "embargoed": False,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY=bz_api_key,
            HTTP_JIRA_API_KEY=user_token,
        )
        assert "Source value is required" in str(response.content)
        assert response.status_code == 400
        assert not flaw.task_key

        # Now use the create_jira_task to force the creation of a task for the flaw
        flaw = Flaw.objects.get(uuid=flaw.uuid)
        response = auth_client().put(
            f"{test_osidb_api_uri}/flaws/{flaw.uuid}?create_jira_task=1",
            {
                "uuid": flaw.uuid,
                "cve_id": flaw.cve_id,
                "title": f"{flaw.title} appended test title",
                "comment_zero": flaw.comment_zero,
                "impact": flaw.impact,
                "source": flaw.source,
                "embargoed": False,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY=bz_api_key,
            HTTP_JIRA_API_KEY=user_token,
        )
        assert response.status_code == 200
        flaw = Flaw.objects.get(uuid=flaw.uuid)
        assert flaw.task_key == "TASK-123"

    @pytest.mark.vcr
    def test_token_validation(self, monkeypatch, acl_read, acl_write, user_token):
        """
        Test that service is able validate user authentication and raise errors
        """
        # Remove randomness to reuse VCR every possible time
        uuid1 = "73cbc51f-4774-4357-a80a-8f433759020f"
        uuid2 = "323e22a9-5cc5-4627-ba66-19c8eea26e51"

        jira_token = user_token
        reported_dt = make_aware(datetime.now())
        flaw = Flaw(
            uuid=uuid1,
            acl_read=acl_read,
            acl_write=acl_write,
            cwe_id="CWE-1",
            impact="LOW",
            components=["kernel"],
            source="REDHAT",
            title="some description",
            comment_zero="test",
            reported_dt=reported_dt,
            unembargo_dt=reported_dt,
        )

        # Valid token; everything should work
        assert flaw.save(jira_token=jira_token) is None
        assert flaw.task_key
        assert Flaw.objects.get(uuid=uuid1)

        flaw = Flaw(
            uuid=uuid2,
            acl_read=acl_read,
            acl_write=acl_write,
            cwe_id="CWE-1",
            impact="LOW",
            components=["kernel"],
            source="REDHAT",
            title="some description",
            comment_zero="test",
            reported_dt=reported_dt,
            unembargo_dt=reported_dt,
        )
        with pytest.raises(
            JIRAError, match="Client must be authenticated to access this resource."
        ):
            # Invalid token; Jira library should raise exception
            flaw.save(jira_token="invalid_token")  # nosec

        assert Flaw.objects.filter(uuid=uuid2).count() == 0

        # enforce project without writing permissions
        import apps.taskman.service as service

        monkeypatch.setattr(service, "JIRA_TASKMAN_PROJECT_KEY", "ISO")

        with pytest.raises(
            TaskWritePermissionsException,
            match="user doesn't have write permission in ISO project.",
        ):
            # Valid token for a project without permissions; should raise custom exception
            flaw.save(jira_token=jira_token)

        assert Flaw.objects.filter(uuid=uuid2).count() == 0
