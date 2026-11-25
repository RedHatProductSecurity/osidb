import time
from threading import Event, Thread

import pghistory
import pytest
from django.conf import settings
from django.db import connection
from rest_framework import status

from osidb.core import set_user_acls
from osidb.models import Affect, Flaw, Tracker
from osidb.serializer import TrackerSerializer
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

    @pytest.mark.parametrize("bts_name", ["bugzilla", "jboss"])
    @pytest.mark.parametrize("operation", ["create", "update"])
    def test_existing_tracker_is_not_stolen(
        self, auth_client, test_api_v2_uri, bts_name, operation
    ):
        stream = PsUpdateStreamFactory(ps_module=PsModuleFactory(bts_name=bts_name))
        affect = AffectFactory(
            ps_update_stream=stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        existing = TrackerFactory(
            affects=[affect],
            status="NEW",
            resolution="",
            ps_update_stream=stream.name,
            type=Tracker.BTS2TYPE[bts_name],
            embargoed=affect.flaw.embargoed,
        )
        other_affect = AffectFactory(
            flaw__embargoed=affect.flaw.embargoed,
            ps_update_stream=stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        other = (
            TrackerFactory(
                affects=[other_affect],
                status="NEW",
                resolution="",
                ps_update_stream=stream.name,
                type=Tracker.BTS2TYPE[bts_name],
                embargoed=affect.flaw.embargoed,
            )
            if operation == "update"
            else None
        )
        if other:
            body = auth_client().get(f"{test_api_v2_uri}/trackers/{other.uuid}").json()
            response = auth_client().put(
                f"{test_api_v2_uri}/trackers/{other.uuid}",
                {**body, "affects": [str(other_affect.uuid), str(affect.uuid)]},
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
        else:
            response = auth_client().post(
                f"{test_api_v2_uri}/trackers",
                {
                    "affects": [str(affect.uuid)],
                    "embargoed": affect.flaw.embargoed,
                    "ps_update_stream": stream.name,
                },
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
        assert response.status_code == 400, response.json()
        error = str(response.json()["affects"])
        assert str(existing.uuid) in error
        assert affect.ps_update_stream in error
        assert affect.ps_component in error
        set_user_acls(settings.ALL_GROUPS)
        affect.refresh_from_db()
        assert affect.tracker_id == existing.uuid
        assert Tracker.objects.count() == (2 if other else 1)

    @pytest.mark.parametrize(
        "status_value,resolution",
        [("CLOSED", ""), ("NEW", "duplicate"), ("NEW", "")],
    )
    def test_tracker_create_existing_tracker_state(
        self, auth_client, test_api_v2_uri, status_value, resolution
    ):
        stream = PsUpdateStreamFactory(ps_module=PsModuleFactory(bts_name="bugzilla"))
        affect = AffectFactory(
            ps_update_stream=stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        existing = TrackerFactory(
            affects=[affect],
            status=status_value,
            resolution=resolution,
            ps_update_stream=stream.name,
            type=Tracker.TrackerType.BUGZILLA,
            embargoed=affect.flaw.embargoed,
        )
        response = auth_client().post(
            f"{test_api_v2_uri}/trackers",
            {
                "affects": [str(affect.uuid)],
                "embargoed": affect.flaw.embargoed,
                "ps_update_stream": stream.name,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 400, response.json()
        assert str(existing.uuid) in str(response.json()["affects"])
        set_user_acls(settings.ALL_GROUPS)
        affect.refresh_from_db()
        assert affect.tracker_id == existing.uuid
        assert Tracker.objects.count() == 1

    @pytest.mark.django_db(transaction=True)
    def test_concurrent_tracker_create_rejects_second_request(
        self, auth_client, test_api_v2_uri, monkeypatch
    ):
        """A second request waits for the first to finish, then gets a 400."""
        stream = PsUpdateStreamFactory(ps_module=PsModuleFactory(bts_name="bugzilla"))
        affect = AffectFactory(
            ps_update_stream=stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        client = auth_client()
        first_locked = Event()
        release_first = Event()
        original_check = TrackerSerializer._check_existing_trackers
        responses = {}
        errors = []

        def check(affects, tracker=None):
            original_check(affects, tracker)
            if not first_locked.is_set():
                first_locked.set()
                assert release_first.wait(timeout=10)

        monkeypatch.setattr(
            TrackerSerializer, "_check_existing_trackers", staticmethod(check)
        )

        def create(index):
            try:
                responses[index] = client.post(
                    f"{test_api_v2_uri}/trackers",
                    {
                        "affects": [str(affect.uuid)],
                        "embargoed": affect.flaw.embargoed,
                        "ps_update_stream": stream.name,
                    },
                    format="json",
                    HTTP_BUGZILLA_API_KEY="SECRET",
                    HTTP_JIRA_API_KEY="SECRET",
                )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)
            finally:
                connection.close()

        first = Thread(target=create, args=(1,))
        second = Thread(target=create, args=(2,))
        first.start()
        try:
            assert first_locked.wait(timeout=10)
            second.start()
            # Do not release the first transaction until PostgreSQL confirms
            # that the second is blocked on the affect row lock.
            deadline = time.monotonic() + 10
            blocked = False
            while time.monotonic() < deadline:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT count(*) FROM pg_stat_activity "
                        "WHERE wait_event_type = 'Lock' AND pid <> pg_backend_pid() "
                        "AND query ILIKE '%osidb_affect%'"
                    )
                    blocked = cursor.fetchone()[0] > 0
                if blocked:
                    break
                time.sleep(0.05)
            assert blocked, "second request never blocked on the affect row lock"
        finally:
            release_first.set()
            first.join(timeout=15)
            if second.ident is not None:
                second.join(timeout=15)
        assert not first.is_alive() and not second.is_alive()
        assert not errors, errors
        assert responses[1].status_code == 201, responses[1].json()
        assert responses[2].status_code == 400, responses[2].json()
        set_user_acls(settings.ALL_GROUPS)
        affect.refresh_from_db()
        assert Tracker.objects.count() == 1
        assert affect.tracker_id == Tracker.objects.get().uuid

    @pytest.mark.enable_signals
    def test_tracker_create_classifies_once(
        self, auth_client, test_api_v2_uri, monkeypatch
    ):
        """Classify the linked flaw once before syncing the tracker."""
        flaw = FlawFactory(task_key="OSIDB-5866")
        stream = PsUpdateStreamFactory(ps_module=PsModuleFactory(bts_name="bugzilla"))
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        original_classify = Flaw.classify
        calls = []

        def classify(instance):
            """Track classification of the linked flaw."""
            if instance.pk == flaw.pk:
                calls.append(instance.pk)
            return original_classify(instance)

        monkeypatch.setattr(Flaw, "classify", classify)
        original_save = Tracker.save

        def save_tracker(instance, *args, **kwargs):
            """Check classification precedes the tracker sync."""
            if not instance._state.adding:
                assert calls == [flaw.pk]
            return original_save(instance, *args, **kwargs)

        monkeypatch.setattr(Tracker, "save", save_tracker)
        response = auth_client().post(
            f"{test_api_v2_uri}/trackers",
            {
                "affects": [str(affect.uuid)],
                "embargoed": flaw.embargoed,
                "ps_update_stream": stream.name,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 201, response.json()
        assert calls == [flaw.pk]

    @pytest.mark.enable_signals
    def test_tracker_create_inaccessible_flaw_returns_validation_error(
        self, auth_client, test_api_v2_uri, monkeypatch
    ):
        """Reject an inaccessible flaw without leaving a tracker or link."""
        flaw = FlawFactory()
        stream = PsUpdateStreamFactory(ps_module=PsModuleFactory(bts_name="bugzilla"))
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        monkeypatch.setattr(Flaw.objects, "in_bulk", lambda ids: {})
        response = auth_client().post(
            f"{test_api_v2_uri}/trackers",
            {
                "affects": [str(affect.uuid)],
                "embargoed": flaw.embargoed,
                "ps_update_stream": stream.name,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 400
        assert "not accessible" in str(response.json()["affects"])
        set_user_acls(settings.ALL_GROUPS)
        assert not Tracker.objects.exists()
        affect.refresh_from_db()
        assert affect.tracker is None

    @pytest.mark.enable_signals
    def test_tracker_update_inaccessible_flaw_returns_validation_error(
        self, auth_client, test_api_v2_uri, monkeypatch
    ):
        """Reject an inaccessible flaw and roll back added links."""
        flaw = FlawFactory()
        stream = PsUpdateStreamFactory(ps_module=PsModuleFactory(bts_name="bugzilla"))
        linked = AffectFactory(
            flaw=flaw,
            ps_update_stream=stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        tracker = TrackerFactory(
            affects=[linked],
            embargoed=flaw.embargoed,
            ps_update_stream=stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )
        other = AffectFactory(
            flaw=FlawFactory(embargoed=flaw.embargoed),
            ps_update_stream=stream.name,
            ps_component=linked.ps_component,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        url = f"{test_api_v2_uri}/trackers/{tracker.uuid}"
        data = auth_client().get(url).json()
        data["affects"].append(str(other.uuid))
        monkeypatch.setattr(Flaw.objects, "in_bulk", lambda ids: {})
        response = auth_client().put(
            url,
            data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 400
        assert "not accessible" in str(response.json()["affects"])
        set_user_acls(settings.ALL_GROUPS)
        other.refresh_from_db()
        assert other.tracker is None
        assert tracker.affects.count() == 1

    @pytest.mark.enable_signals
    def test_tracker_links_classify_once(
        self, auth_client, test_api_v2_uri, monkeypatch
    ):
        """Classify only the flaw whose tracker link changed."""
        flaw = FlawFactory(task_key="OSIDB-5866")
        other_flaw = FlawFactory(task_key="OSIDB-5867", embargoed=flaw.embargoed)
        stream = PsUpdateStreamFactory(ps_module=PsModuleFactory(bts_name="bugzilla"))
        affects = [
            AffectFactory(
                flaw=parent,
                ps_update_stream=stream.name,
                ps_component="shared-component",
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
            )
            for parent in (flaw, other_flaw)
        ]
        tracker = TrackerFactory(
            affects=[affects[0]],
            embargoed=flaw.embargoed,
            ps_update_stream=stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )
        original_classify = Flaw.classify
        calls = []

        def classify(instance):
            """Track classification of both candidate flaws."""
            if instance.pk in (flaw.pk, other_flaw.pk):
                calls.append(instance.pk)
            return original_classify(instance)

        monkeypatch.setattr(Flaw, "classify", classify)
        original_save = Tracker.save

        def save_tracker(instance, *args, **kwargs):
            """Check only the newly linked flaw was classified."""
            assert calls == [other_flaw.pk]
            return original_save(instance, *args, **kwargs)

        monkeypatch.setattr(Tracker, "save", save_tracker)
        url = f"{test_api_v2_uri}/trackers/{tracker.uuid}"
        data = auth_client().get(url).json()
        data["affects"] = [str(affect.uuid) for affect in affects]
        response = auth_client().put(
            url,
            data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200, response.json()
        assert tracker.affects.count() == 2
        assert calls == [other_flaw.pk]

    @pytest.mark.enable_signals
    def test_tracker_create_history_context_is_scoped_per_flaw(
        self, auth_client, test_api_v2_uri, monkeypatch
    ):
        """Attribute each batch Flaw save only to its own changed Affect."""
        flaws = [
            FlawFactory(task_key=f"OSIDB-{key}", embargoed=False)
            for key in (5866, 5867)
        ]
        stream = PsUpdateStreamFactory(ps_module=PsModuleFactory(bts_name="bugzilla"))
        affects = [
            AffectFactory(
                flaw=flaw,
                ps_update_stream=stream.name,
                ps_component="shared-component",
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
            )
            for flaw in flaws
        ]
        original_save = Flaw.save
        contexts = {}
        flaw_ids = {flaw.pk for flaw in flaws}

        def save_flaw(instance, *args, **kwargs):
            """Capture the pghistory context active during each Flaw save."""
            if instance.pk in flaw_ids:
                contexts[instance.pk] = pghistory.runtime._tracker.value.metadata.copy()
            return original_save(instance, *args, **kwargs)

        monkeypatch.setattr(Flaw, "save", save_flaw)
        response = auth_client().post(
            f"{test_api_v2_uri}/trackers",
            {
                "affects": [str(affect.uuid) for affect in affects],
                "embargoed": flaws[0].embargoed,
                "ps_update_stream": stream.name,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 201, response.json()
        for flaw, affect in zip(flaws, affects):
            assert contexts[flaw.pk]["signal"] == "update_local_updated_dt_affect"
            assert contexts[flaw.pk]["instance"] == [str(affect.uuid)]

    @pytest.mark.enable_signals
    def test_tracker_create_sync_failure_rolls_back(
        self, auth_client, test_api_v2_uri, monkeypatch
    ):
        """Roll back the tracker and its link when backend sync fails."""
        flaw = FlawFactory()
        stream = PsUpdateStreamFactory(ps_module=PsModuleFactory(bts_name="bugzilla"))
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        original_save = Tracker.save
        calls = []

        def fail_sync(instance, *args, **kwargs):
            """Fail the second tracker save to exercise rollback."""
            calls.append(instance.pk)
            if len(calls) == 2:
                raise RuntimeError("tracker sync failed")
            return original_save(instance, *args, **kwargs)

        monkeypatch.setattr(Tracker, "save", fail_sync)
        with pytest.raises(RuntimeError, match="tracker sync failed"):
            auth_client().post(
                f"{test_api_v2_uri}/trackers",
                {
                    "affects": [str(affect.uuid)],
                    "embargoed": flaw.embargoed,
                    "ps_update_stream": stream.name,
                },
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
        set_user_acls(settings.ALL_GROUPS)
        assert len(calls) == 2
        assert not Tracker.objects.exists()
        affect.refresh_from_db()
        assert affect.tracker is None

    @pytest.mark.enable_signals
    def test_tracker_link_sync_failure_rolls_back(
        self, auth_client, test_api_v2_uri, monkeypatch
    ):
        """Restore both flaws' classification and links after sync failure."""
        flaw = FlawFactory(task_key="OSIDB-5866")
        stream = PsUpdateStreamFactory(ps_module=PsModuleFactory(bts_name="bugzilla"))
        linked = AffectFactory(
            flaw=flaw,
            ps_update_stream=stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        tracker = TrackerFactory(
            affects=[linked],
            embargoed=flaw.embargoed,
            ps_update_stream=stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )
        other_flaw = FlawFactory(task_key="OSIDB-5867", embargoed=flaw.embargoed)
        unlinked = AffectFactory(
            flaw=other_flaw,
            ps_update_stream=stream.name,
            ps_component=linked.ps_component,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        original_state = flaw.workflow_state
        original_other_state = other_flaw.workflow_state
        url = f"{test_api_v2_uri}/trackers/{tracker.uuid}"
        data = auth_client().get(url).json()
        data["affects"].append(str(unlinked.uuid))

        def fail_sync(*args, **kwargs):
            """Simulate failure after updating the tracker links."""
            raise RuntimeError("tracker sync failed")

        monkeypatch.setattr(Tracker, "save", fail_sync)
        with pytest.raises(RuntimeError, match="tracker sync failed"):
            auth_client().put(
                url,
                data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
        set_user_acls(settings.ALL_GROUPS)
        unlinked.refresh_from_db()
        assert unlinked.tracker is None
        assert tracker.affects.count() == 1
        flaw.refresh_from_db()
        assert flaw.workflow_state == original_state
        other_flaw.refresh_from_db()
        assert other_flaw.workflow_state == original_other_state

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
        """Include the linked flaw's CVE ID in tracker detail."""
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
        """Filter trackers by their linked flaw's CVE ID."""
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
