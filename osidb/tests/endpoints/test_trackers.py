import pytest
from rest_framework import status

from apps.ace.constants import LABEL_AUTO_AFFECTS, LABEL_MANUAL_TRIAGE
from apps.bbsync.mixins import BugzillaSyncMixin
from osidb.models import Affect, Flaw, Tracker
from osidb.models.flaw.label import WorkflowLabel
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def captured_tracker_saves(monkeypatch):
    captured = []
    original_save = Tracker.save

    def wrapped(
        self, *args, bz_api_key=None, jira_token=None, jira_email=None, **kwargs
    ):
        captured.append((bz_api_key, jira_token, jira_email))
        return original_save(
            self, *args, bz_api_key=None, jira_token=None, jira_email=None, **kwargs
        )

    monkeypatch.setattr(Tracker, "save", wrapped)
    return captured


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

    def test_tracker_create_auto_affects_uses_service_credentials(
        self, auth_client, test_api_v2_uri, monkeypatch, captured_tracker_saves
    ):
        """Auto-analyzed flaws file trackers with the OSIDB service account."""
        service = ("service-bz", "service-jira", "service@example.com")
        caller = ("caller-bz", "caller-jira", "caller@example.com")
        monkeypatch.setattr("collectors.bzimport.constants.BZ_API_KEY", service[0])
        monkeypatch.setattr("apps.taskman.constants.JIRA_AUTH_TOKEN", service[1])
        monkeypatch.setattr("apps.taskman.constants.JIRA_EMAIL", service[2])

        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw__embargoed=False,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        WorkflowLabel.objects.create(flaw=affect.flaw, name=LABEL_AUTO_AFFECTS)

        response = auth_client().post(
            f"{test_api_v2_uri}/trackers",
            {
                "affects": [affect.uuid],
                "embargoed": False,
                "ps_update_stream": ps_update_stream.name,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY=caller[0],
            HTTP_JIRA_API_KEY=caller[1],
            HTTP_JIRA_API_EMAIL=caller[2],
        )

        assert response.status_code == status.HTTP_201_CREATED
        bts_saves = [
            creds for creds in captured_tracker_saves if creds != (None, None, None)
        ]
        assert service in bts_saves
        assert caller not in bts_saves

    def test_tracker_create_auto_affects_missing_service_credentials(
        self, auth_client, test_api_v2_uri, monkeypatch
    ):
        """Unconfigured service Jira credentials must not create an unfiled tracker."""
        caller = ("caller-bz", "caller-jira", "caller@example.com")
        monkeypatch.setattr("collectors.bzimport.constants.BZ_API_KEY", "service-bz")
        monkeypatch.setattr("apps.taskman.constants.JIRA_AUTH_TOKEN", None)
        monkeypatch.setattr("apps.taskman.constants.JIRA_EMAIL", "service@example.com")

        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw__embargoed=False,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        WorkflowLabel.objects.create(flaw=affect.flaw, name=LABEL_AUTO_AFFECTS)

        assert Tracker.objects.count() == 0
        response = auth_client().post(
            f"{test_api_v2_uri}/trackers",
            {
                "affects": [affect.uuid],
                "embargoed": False,
                "ps_update_stream": ps_update_stream.name,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY=caller[0],
            HTTP_JIRA_API_KEY=caller[1],
            HTTP_JIRA_API_EMAIL=caller[2],
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Jira-Api-Key" in response.json()
        assert Tracker.objects.count() == 0

    def test_tracker_create_manual_triage_uses_caller_credentials(
        self, auth_client, test_api_v2_uri, monkeypatch, captured_tracker_saves
    ):
        """MANUAL / manual-triage flaws keep the caller's BTS credentials."""
        service = ("service-bz", "service-jira", "service@example.com")
        caller = ("caller-bz", "caller-jira", "caller@example.com")
        monkeypatch.setattr("collectors.bzimport.constants.BZ_API_KEY", service[0])
        monkeypatch.setattr("apps.taskman.constants.JIRA_AUTH_TOKEN", service[1])
        monkeypatch.setattr("apps.taskman.constants.JIRA_EMAIL", service[2])

        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw__embargoed=False,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        WorkflowLabel.objects.create(flaw=affect.flaw, name=LABEL_MANUAL_TRIAGE)

        response = auth_client().post(
            f"{test_api_v2_uri}/trackers",
            {
                "affects": [affect.uuid],
                "embargoed": False,
                "ps_update_stream": ps_update_stream.name,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY=caller[0],
            HTTP_JIRA_API_KEY=caller[1],
            HTTP_JIRA_API_EMAIL=caller[2],
        )

        assert response.status_code == status.HTTP_201_CREATED
        bts_saves = [
            creds for creds in captured_tracker_saves if creds != (None, None, None)
        ]
        assert caller in bts_saves
        assert service not in bts_saves

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
