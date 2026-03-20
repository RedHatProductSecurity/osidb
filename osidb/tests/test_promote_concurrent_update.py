"""
Test for CVE-2026-2758 using concurrent update injection

This test injects a concurrent update DURING the promote operation
to simulate what happened in the real incident.
"""
import pytest
from unittest.mock import patch
from django.utils import timezone
from freezegun import freeze_time
from rest_framework import status

from osidb.models import Affect, Flaw, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

from collections import defaultdict
from datetime import timedelta
pytestmark = pytest.mark.unit


@pytest.mark.enable_signals
class TestPromoteConcurrentUpdate:
    """Test CVE-2026-2758 by injecting concurrent update during promotion"""

    @pytest.mark.enable_signals
    @freeze_time("2024-03-06 18:16:00")
    def test_concurrent_collector_update_during_promote(
        self, auth_client, test_api_uri, jira_token, bugzilla_token
    ):
        """
        Simulate the exact CVE-2026-2758 race condition:

        1. User starts POST /promote (loads Flaw B via prefetch)
        2. DURING the promote operation, collector updates Flaw B
        3. Promotion continues and signal tries to save stale Flaw B
        4. Optimistic locking should detect this and raise error

        We use a patch to inject the concurrent update mid-request.
        """
        # Setup: Two flaws sharing a tracker
        ps_module = PsModuleFactory()
        component = "shared-component"

        # Create a user for the flaw owner
        from django.contrib.auth import get_user_model
        User = get_user_model()
        owner, _ = User.objects.get_or_create(username="testowner", defaults={"email": "test@example.com"})

        ps_update_streams = [PsUpdateStreamFactory(ps_module=ps_module) for _ in range(10)]
        
        # create a lot of flaws with specific timestamps for each flaw
        all_affects = defaultdict(list)
        all_flaws = []
        new_flaw_time = timezone.now()
        for i in range(10):
            cve_id = f"CVE-2026-{i+1:04d}"
            flaw = FlawFactory(
                embargoed=False,
                cve_id=cve_id,
                title=f"Flaw {i} - to be promoted",
                comment_zero=f"Flaw {i} description",
                workflow_state="NEW",
                updated_dt=timezone.now(),
                owner=owner.username,  # Add owner
                task_key="OSIM-12345",  # Add task_key for workflow
            )
            new_flaw_time = new_flaw_time + timedelta(seconds=i)
            all_flaws.append(flaw)
            for j in range(10):
                affect = AffectFactory(
                    flaw=flaw,
                    affectedness=Affect.AffectAffectedness.AFFECTED,
                    resolution=Affect.AffectResolution.DELEGATED,
                    ps_update_stream=ps_update_streams[j].name,
                    ps_component=component,
                )
                with freeze_time(new_flaw_time+timedelta(microseconds=j*1000)):
                    affect.save()
                all_affects[j].append(affect)
                print(f'Done {i}/{j}')

        all_trackers = []
        for k, affects_list in all_affects.items():
            shared_tracker = TrackerFactory(
            affects=affects_list,
            embargoed=False,
            ps_update_stream=ps_update_streams[k].name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            external_system_id=f"SHARED-TRACKER-{k}",
        )
            all_trackers.append(shared_tracker)
            

        flaw_a = all_flaws[0]
        flaw_b = all_flaws[1]
        flaw_a_uuid = flaw_a.uuid
        flaw_b_uuid = flaw_b.uuid

        # Debug: Check if signals are actually enabled
        from django.db.models.signals import pre_save
        print(f"\n[DEBUG] pre_save signal has {len(pre_save.receivers)} receivers")

        # Track whether we've injected the update
        update_injected = {'done': False}

        # Import the original signal handler
        from osidb import signals
        original_update_flaw_fields = signals.update_flaw_fields
        original_update_tracker = signals.update_local_updated_dt_tracker

        def patched_update_flaw_fields(sender, instance, **kwargs):
            """
            Patch the pre_save signal on Flaw to inject concurrent update
            """
            print(f"[DEBUG] update_flaw_fields called for: {instance.cve_id if hasattr(instance, 'cve_id') else instance}")

            # Only inject once, when Flaw A is being saved
            if not update_injected['done'] and hasattr(instance, 'cve_id') and instance.cve_id == "CVE-2026-0001":
                update_injected['done'] = True

                print(f"\n=== INJECTING CONCURRENT UPDATE ===")
                print(f"Currently saving: {instance.cve_id}")

                # Simulate collector updating Flaw B RIGHT NOW
                flaw_b_fresh = Flaw.objects.get(uuid=flaw_b_uuid)
                print(f"Before update: {flaw_b_fresh.comment_zero}")

                flaw_b_fresh.comment_zero = "Updated by collector DURING promotion with SeaMonkey"
                flaw_b_fresh.save()

                flaw_b_check = Flaw.objects.get(uuid=flaw_b_uuid)
                print(f"After update: {flaw_b_check.comment_zero}")
                print(f"Updated_dt: {flaw_b_check.updated_dt}")
                print(f"=== UPDATE INJECTED ===\n")

            # Call original signal
            return original_update_flaw_fields(sender, instance, **kwargs)

        def patched_update_tracker(sender, instance, **kwargs):
            """Patch the tracker signal to see when it fires"""
            print(f"[DEBUG] update_local_updated_dt_tracker called for: {sender.__name__}")
            return original_update_tracker(sender, instance, **kwargs)

        # Patch both signal handlers to see what's firing
        with patch.object(signals, 'update_flaw_fields', patched_update_flaw_fields), \
             patch.object(signals, 'update_local_updated_dt_tracker', patched_update_tracker):
            # Now do the promote
            response = auth_client().post(
                f"{test_api_uri}/flaws/{flaw_a_uuid}/promote",
                data={},
                format="json",
                HTTP_JIRA_API_KEY=jira_token,
                HTTP_BUGZILLA_API_KEY=bugzilla_token,
            )

        print(f"\n=== RESPONSE ===")
        print(f"Status: {response.status_code}")
        if response.status_code != status.HTTP_200_OK:
            print(f"Response data: {response.data}")

        # Check final state of Flaw B
        flaw_b_final = Flaw.objects.get(uuid=flaw_b_uuid)
        print(f"\n=== FLAW B FINAL STATE ===")
        print(f"Description: {flaw_b_final.comment_zero}")
        print(f"Updated_dt: {flaw_b_final.updated_dt}")
        print(f"Has SeaMonkey: {'SeaMonkey' in flaw_b_final.comment_zero}")

        # Verify the update was injected
        assert update_injected['done'], "Test didn't inject the update - something's wrong"

        if response.status_code == status.HTTP_200_OK:
            # Bug present - Flaw B was corrupted
            assert "SeaMonkey" in flaw_b_final.comment_zero, (
                "BUG DETECTED! Flaw B was corrupted during promotion. "
                f"Expected 'SeaMonkey', got: {flaw_b_final.comment_zero}"
            )
        else:
            # Optimistic locking worked!
            assert response.status_code in [
                status.HTTP_409_CONFLICT,
                status.HTTP_500_INTERNAL_SERVER_ERROR,
            ], f"Unexpected status: {response.status_code}"

            # Verify Flaw B still has the concurrent update
            assert "SeaMonkey" in flaw_b_final.comment_zero, (
                f"Flaw B should have SeaMonkey, got: {flaw_b_final.comment_zero}"
            )

    @freeze_time("2024-03-06 18:16:00")
    def test_concurrent_update_during_affect_save(
        self, auth_client, test_api_uri, jira_token, bugzilla_token
    ):
        """
        Alternative: Concurrent update during Affect PUT

        This also triggers the update_local_updated_dt_tracker signal
        """
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        component = "shared"

        flaw_a = FlawFactory(
            embargoed=False,
            cve_id="CVE-2026-0001",
            comment_zero="Flaw A",
            updated_dt=timezone.now(),
        )

        flaw_b = FlawFactory(
            embargoed=False,
            cve_id="CVE-2026-0002",
            comment_zero="Original Flaw B",
            updated_dt=timezone.now(),
        )

        affect_a = AffectFactory(
            flaw=flaw_a,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component=component,
        )

        affect_b = AffectFactory(
            flaw=flaw_b,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component=component,
        )

        tracker = TrackerFactory(
            affects=[affect_a, affect_b],
            embargoed=False,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            external_system_id="SHARED-TRACKER",
        )

        # Get the affect data
        response = auth_client().get(
            f"{test_api_uri}/affects/{affect_a.uuid}",
            format="json",
        )
        affect_data = response.json()

        flaw_b_uuid = flaw_b.uuid
        update_injected = {'done': False}

        # Patch the Affect pre_save signal
        from osidb import signals

        # We need to patch at the point where Affect is being saved
        # Use the flaw_dependant_update_local_updated_dt signal
        original_signal = signals.flaw_dependant_update_local_updated_dt

        def patched_signal(sender, instance, **kwargs):
            """Inject update when Affect is saved"""
            if not update_injected['done'] and sender.__name__ == 'Affect':
                update_injected['done'] = True

                print(f"\n=== INJECTING CONCURRENT UPDATE (Affect save) ===")

                # Collector updates Flaw B
                flaw_b_fresh = Flaw.objects.get(uuid=flaw_b_uuid)
                flaw_b_fresh.comment_zero = "Updated by collector DURING affect save"
                flaw_b_fresh.save()

                print(f"Updated Flaw B during Affect save")
                print(f"=== UPDATE INJECTED ===\n")

            # Call original
            return original_signal(sender, instance, **kwargs)

        with patch.object(signals, 'flaw_dependant_update_local_updated_dt', patched_signal):
            # Update the affect
            affect_data["impact"] = "MODERATE"
            response = auth_client().put(
                f"{test_api_uri}/affects/{affect_a.uuid}",
                data=affect_data,
                format="json",
            )

        print(f"\n=== RESPONSE ===")
        print(f"Status: {response.status_code}")

        flaw_b_final = Flaw.objects.get(uuid=flaw_b_uuid)
        print(f"\n=== FLAW B FINAL STATE ===")
        print(f"Description: {flaw_b_final.comment_zero}")

        if response.status_code == status.HTTP_200_OK:
            # Check if corrupted
            assert "DURING affect save" in flaw_b_final.comment_zero, (
                f"BUG: Flaw B corrupted, got: {flaw_b_final.comment_zero}"
            )
        else:
            # Optimistic locking worked
            assert response.status_code in [
                status.HTTP_409_CONFLICT,
                status.HTTP_500_INTERNAL_SERVER_ERROR,
            ]
