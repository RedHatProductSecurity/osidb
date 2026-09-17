from types import SimpleNamespace

import pytest
from rest_framework import status

from apps.bbsync.mixins import BugzillaSyncMixin
from collectors.jiraffe.exceptions import NonRecoverableJiraffeException
from osidb.models import Affect, Flaw, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestEndpointsTrackers:
    """
    tests specific to /trackers endpoint
    """

    @pytest.mark.parametrize("bts_name", ["bugzilla", "jboss"])
    @pytest.mark.parametrize("embargoed", [False, True])
    def test_tracker_create(self, auth_client, test_api_v2_uri, embargoed, bts_name):
        """
        Test the creation of Tracker records via a REST API POST request.
        """
        ps_module = PsModuleFactory(bts_name=bts_name)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw__embargoed=embargoed,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )

        assert Tracker.objects.count() == 0

        tracker_data = {
            "affects": [affect.uuid],
            "embargoed": embargoed,
            "ps_update_stream": ps_update_stream.name,
        }
        response = auth_client().post(
            f"{test_api_v2_uri}/trackers",
            tracker_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert Tracker.objects.count() == 1
        tracker = Tracker.objects.first()
        assert tracker.affects.count() == 1
        assert tracker.affects.first().uuid == affect.uuid

    @pytest.mark.parametrize("sync_to_bz", [False, True, None])
    def test_tracker_create_jira_bulk_enablement(
        self, auth_client, test_api_v2_uri, monkeypatch, sync_to_bz
    ):
        """
        Test the creation of Tracker records via a REST API POST request
        with regard to the parameter "sync_to_bz" that disables
        Flaw BZ sync after Tracker creation.
        """

        shared_state = {"runs": []}
        assert len(shared_state["runs"]) == 0

        def patched_save(self, *args, bz_api_key=None, **kwargs):
            success = {"success": False}
            shared_state["runs"].append((self.__class__, success))

            # Original code from the original .save():
            # always perform the validations first
            self.validate(
                raise_validation_error=kwargs.get("raise_validation_error", True)
            )

            # check BBSync conditions are met

            # 3 lines of original .save() disabled so that the test doesn't hit Bugzilla:
            # if SYNC_TO_BZ and bz_api_key is not None:
            #     self.bzsync(*args, bz_api_key=bz_api_key, **kwargs)
            # else:
            super(BugzillaSyncMixin, self).save(*args, **kwargs)
            success["success"] = True

        with monkeypatch.context() as m:
            m.setattr(BugzillaSyncMixin, "save", patched_save)

            assert len(shared_state["runs"]) == 0  # nothing created yet
            ps_module = PsModuleFactory(bts_name="jboss")
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            affect = AffectFactory(
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_update_stream=ps_update_stream.name,
            )

            assert Tracker.objects.count() == 0
            assert Flaw.objects.count() == 1
            assert len(shared_state["runs"]) == 2  # created Flaw and Affect
            assert shared_state == {
                "runs": [
                    (Flaw, {"success": True}),
                    (Affect, {"success": True}),
                ]
            }

            tracker_data = {
                "affects": [affect.uuid],
                "embargoed": affect.flaw.embargoed,
                "ps_update_stream": ps_update_stream.name,
                "sync_to_bz": sync_to_bz,
            }
            if sync_to_bz is None:
                del tracker_data["sync_to_bz"]
            response = auth_client().post(
                f"{test_api_v2_uri}/trackers",
                tracker_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )

            assert response.status_code == status.HTTP_201_CREATED
            assert Tracker.objects.count() == 1
            tracker = Tracker.objects.first()
            assert tracker.affects.count() == 1
            assert tracker.affects.first().uuid == affect.uuid

            if sync_to_bz is False:
                # sync_to_bz=False now schedules an async BZ sync instead of
                # syncing synchronously, so no additional Flaw.save() call happen here
                assert len(shared_state["runs"]) == 3
            else:
                # Flaw is synced synchronously when sync_to_bz is True or None (default)
                assert len(shared_state["runs"]) == 4
                assert shared_state["runs"][-1] == (Flaw, {"success": True})

    @pytest.mark.parametrize("bts_name", ["bugzilla", "jboss"])
    @pytest.mark.parametrize("embargoed", [False, True])
    def test_tracker_update(self, auth_client, test_api_v2_uri, embargoed, bts_name):
        """
        Test the update of Tracker records via a REST API PUT request.
        """
        ps_module = PsModuleFactory(bts_name=bts_name)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw__embargoed=embargoed,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )
        response = auth_client().get(f"{test_api_v2_uri}/trackers/{tracker.uuid}")
        assert response.status_code == 200
        original_body = response.json()

        response = auth_client().put(
            f"{test_api_v2_uri}/trackers/{tracker.uuid}",
            {
                **original_body,
                "resolution": "this is different",
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200

    @pytest.mark.parametrize("bts_name", ["bugzilla", "jboss"])
    @pytest.mark.parametrize("embargoed", [False, True])
    def test_tracker_update_link(
        self, auth_client, test_api_v2_uri, embargoed, bts_name
    ):
        """
        Test the update of Tracker records via a REST API PUT request.
        """
        flaw1 = FlawFactory(embargoed=embargoed)
        flaw2 = FlawFactory(embargoed=embargoed)
        ps_module = PsModuleFactory(bts_name=bts_name)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect1 = AffectFactory(
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        tracker = TrackerFactory(
            affects=[affect1],
            embargoed=affect1.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        response = auth_client().get(f"{test_api_v2_uri}/trackers/{tracker.uuid}")
        assert response.status_code == 200
        original_body = response.json()
        assert affect1.uuid in response.data["affects"]
        assert affect2.uuid not in response.data["affects"]

        response = auth_client().put(
            f"{test_api_v2_uri}/trackers/{tracker.uuid}",
            {
                **original_body,
                "affects": [
                    affect2.uuid
                ],  # remove the first affect and add the second one
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        assert affect1.uuid not in response.data["affects"]
        assert affect2.uuid in response.data["affects"]

    @pytest.mark.parametrize("bts_name", ["bugzilla", "jboss"])
    def test_tracker_delete(self, auth_client, test_api_v2_uri, bts_name):
        """
        Test the deletion of Tracker records via a REST API DELETE request.
        """
        ps_module = PsModuleFactory(bts_name=bts_name)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )
        tracker_url = f"{test_api_v2_uri}/trackers/{tracker.uuid}"
        response = auth_client().get(tracker_url)
        assert response.status_code == 200

        response = auth_client().delete(tracker_url)
        # this HTTP method is not allowed until we integrate
        # with the authoritative sources of the tracker data
        assert response.status_code == 405

    @pytest.mark.enable_signals
    def test_get_tracker_with_cve_id(self, auth_client, test_api_uri):
        flaw = FlawFactory(cve_id="CVE-2025-1234")
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        response = auth_client().get(f"{test_api_uri}/trackers/{tracker.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["cve_id"] == flaw.cve_id

    @pytest.mark.enable_signals
    def test_filter_tracker_by_cve_id(self, auth_client, test_api_uri):
        flaw = FlawFactory(cve_id="CVE-2025-1234")
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        response = auth_client().get(f"{test_api_uri}/trackers?cve_id={flaw.cve_id}")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["count"] == 1
        assert response.data["results"][0]["cve_id"] == flaw.cve_id

    def test_link_affects_endpoint(self, auth_client, test_api_v2_uri, monkeypatch):
        """
        Test the on-demand link-affects endpoint triggers a Jira re-fetch
        and relinks the tracker to its affects.
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            flaw__embargoed=False,
        )
        tracker = TrackerFactory(
            affects=[affect],
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        mock_issue = SimpleNamespace(
            key="JIRA-1234",
            fields=SimpleNamespace(
                summary="Test summary",
                labels=[],
                created="2024-01-01T00:00:00.000+0000",
                updated=None,
                resolutiondate=None,
                status=SimpleNamespace(name="New"),
                issuetype=SimpleNamespace(name="Bug"),
                resolution=None,
                security=None,
                customfield_10832=None,
                customfield_10873=None,
                customfield_10670=None,
            ),
        )

        monkeypatch.setattr(
            "osidb.api_views.JiraQuerier.get_issue",
            lambda self, issue_id: mock_issue,
        )
        monkeypatch.setattr(
            "collectors.jiraffe.convertors.JiraTrackerConvertor.tracker",
            property(lambda self: None),
        )
        monkeypatch.setattr(
            "osidb.api_views.JiraTrackerDownloadManager.link_tracker_with_affects",
            staticmethod(lambda tracker_id: ([affect], [], [])),
        )

        response = auth_client().post(
            f"{test_api_v2_uri}/trackers/{tracker.uuid}/link-affects"
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data["failed_flaws"] == []
        assert response.data["failed_affects"] == []
        assert len(response.data["affects"]) == 1
        assert response.data["affects"][0]["uuid"] == str(affect.uuid)

    def test_link_affects_endpoint_rejects_bugzilla_tracker(
        self, auth_client, test_api_v2_uri, monkeypatch
    ):
        """
        Test the link-affects endpoint rejects non-Jira trackers
        without invoking any Jira handling.
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            flaw__embargoed=False,
        )
        tracker = TrackerFactory(
            affects=[affect],
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        def fail_if_called(*args, **kwargs):
            raise AssertionError(
                "JiraQuerier.get_issue should not be called for a Bugzilla tracker"
            )

        monkeypatch.setattr("osidb.api_views.JiraQuerier.get_issue", fail_if_called)

        response = auth_client().post(
            f"{test_api_v2_uri}/trackers/{tracker.uuid}/link-affects"
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_link_affects_endpoint_rejects_empty_external_system_id(
        self, auth_client, test_api_v2_uri, monkeypatch
    ):
        """
        Test the link-affects endpoint returns 400 for a Jira tracker
        with no external_system_id, without calling Jira.
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            flaw__embargoed=False,
        )
        tracker = TrackerFactory(
            affects=[affect],
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            external_system_id="",
        )

        def fail_if_called(*args, **kwargs):
            raise AssertionError(
                "JiraQuerier.get_issue should not be called when external_system_id is empty"
            )

        monkeypatch.setattr("osidb.api_views.JiraQuerier.get_issue", fail_if_called)

        response = auth_client().post(
            f"{test_api_v2_uri}/trackers/{tracker.uuid}/link-affects"
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_link_affects_endpoint_handles_missing_jira_issue(
        self, auth_client, test_api_v2_uri, monkeypatch
    ):
        """
        Test the link-affects endpoint returns 422 when the tracker's Jira issue cannot be fetched.
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            flaw__embargoed=False,
        )
        tracker = TrackerFactory(
            affects=[affect],
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        def raise_not_found(*args, **kwargs):
            raise NonRecoverableJiraffeException("Jira issue not found")

        monkeypatch.setattr("osidb.api_views.JiraQuerier.get_issue", raise_not_found)

        response = auth_client().post(
            f"{test_api_v2_uri}/trackers/{tracker.uuid}/link-affects"
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
