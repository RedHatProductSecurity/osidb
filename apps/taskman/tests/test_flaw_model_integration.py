from datetime import datetime

import pytest
from django.utils.timezone import make_aware
from rest_framework.response import Response

import apps.taskman.mixins as mixins
import osidb.serializer as serializer
from apps.taskman.service import JiraTaskmanQuerier
from osidb.models import Flaw, FlawSource, FlawType, Impact
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

        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", mock_create_or_update_task
        )

        flaw1 = FlawFactory(cve_id="CVE-2020-8002")
        AffectFactory(flaw=flaw1)

        # simulate that flaw was created in osidb, having a jira task associated
        monkeypatch.setattr(
            JiraTaskmanQuerier, "get_task_by_flaw", mock_get_task_existing
        )

        # no important changes requires no syncing
        assert flaw1.tasksync(jira_token=user_token) is None
        assert sync_count == 0

        flaw1.cve_id = "CVE-2020-8003"
        assert flaw1.tasksync(jira_token=user_token) is None
        assert sync_count == 1

        # simulate that flaw was created by a collector, not having a jira task associated
        monkeypatch.setattr(
            JiraTaskmanQuerier, "get_task_by_flaw", mock_get_task_missing
        )

        flaw2 = FlawFactory(cve_id="CVE-2020-8004")
        AffectFactory(flaw=flaw2)
        flaw1.cve_id = "CVE-2020-8005"
        assert flaw1.tasksync(jira_token=user_token) is None
        # flaws created by collectors should not sync in jira
        assert sync_count == 1

    def test_syncing(self, monkeypatch, acl_read, acl_write, user_token):
        sync_count = 0

        def mock_create_or_update_task(self, flaw):
            nonlocal sync_count
            sync_count += 1

        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", mock_create_or_update_task
        )
        monkeypatch.setattr(
            JiraTaskmanQuerier, "get_task_by_flaw", mock_get_task_existing
        )
        monkeypatch.setattr(mixins, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)

        flaw = Flaw(
            cve_id="CVE-2020-8004",
            title="CVE-2020-8004 kernel: some description",
            type=FlawType.VULNERABILITY,
            acl_read=acl_read,
            acl_write=acl_write,
            description="Description",
            component="component",
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

        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", mock_create_or_update_task
        )
        monkeypatch.setattr(serializer, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)

        flaw_data = {
            "cwe_id": "CWE-1",
            "title": "Foo",
            "type": "VULNERABILITY",
            "state": "NEW",
            "impact": "CRITICAL",
            "component": "curl",
            "source": "INTERNET",
            "description": "test",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "embargoed": False,
        }
        response = auth_client.post(
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

        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", mock_create_or_update_task
        )
        monkeypatch.setattr(
            JiraTaskmanQuerier, "get_task_by_flaw", mock_get_task_existing
        )
        monkeypatch.setattr(serializer, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)

        flaw = FlawFactory(embargoed=False, impact=Impact.IMPORTANT)
        AffectFactory(flaw=flaw)
        response = auth_client.get(f"{test_osidb_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200

        response = auth_client.put(
            f"{test_osidb_api_uri}/flaws/{flaw.uuid}",
            {
                "uuid": flaw.uuid,
                "cve_id": flaw.cve_id,
                "type": flaw.type,
                "title": f"{flaw.title} appended test title",
                "description": flaw.description,
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
        response = auth_client.put(
            f"{test_osidb_api_uri}/flaws/{flaw.uuid}",
            {
                "uuid": flaw.uuid,
                "cve_id": flaw.cve_id,
                "type": flaw.type,
                "title": f"{flaw.title} appended test title",
                "description": flaw.description,
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
