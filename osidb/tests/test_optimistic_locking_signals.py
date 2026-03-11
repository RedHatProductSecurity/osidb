"""
Test optimistic locking in signal handlers (CVE-2026-2758 regression tests)

This module tests that signal handlers properly detect race conditions when
child entities are saved with stale parent Flaw objects in memory.

The CVE-2026-2758 incident scenario:
1. User loads Flaw into browser memory at 17:22
2. NVD collector updates the same Flaw in DB at 18:03
3. User saves a child entity (Affect/CVSS) at 18:16
4. Signal handler fires with stale Flaw from 17:22
5. Without proper checks, stale Flaw overwrites fresh DB data

These tests verify that the system detects this race condition.
"""
import uuid

import pytest
from django.utils import timezone
from freezegun import freeze_time

from osidb.core import generate_acls
from osidb.exceptions import DataInconsistencyException
from osidb.models import Affect, Flaw, FlawCVSS, FlawSource, Impact
from osidb.tests.factories import AffectCVSSFactory, AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


def get_acl_read():
    return [
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
        )
    ]


def get_acl_write():
    return [
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            "https://osidb.prod.redhat.com/ns/acls#data-prodsec-write",
        )
    ]


@pytest.mark.enable_signals
class TestOptimisticLockingInSignals:
    """Test that signal handlers respect optimistic locking"""

    @freeze_time("2024-03-06 17:22:00")
    def test_signal_detects_concurrent_flaw_modification_via_affect_save(self):
        """
        Test that saving an Affect with a stale parent Flaw raises DataInconsistencyException

        Scenario (CVE-2026-2758 reproduction):
        1. User loads Flaw+Affect into memory at 17:22
        2. NVD collector updates Flaw in DB at 18:03
        3. User saves Affect at 18:16 (signal tries to save stale Flaw)
        4. Expected: DataInconsistencyException raised
        """
        # Step 1: Create Flaw and Affect, simulating user loading them at 17:22
        flaw = FlawFactory(
            embargoed=False,
            title="Original Title",
            comment_zero="Original description without Thunderbird",
        )
        affect = AffectFactory(flaw=flaw)

        # Reload to get the same timestamps as in DB
        flaw_in_memory = Flaw.objects.get(pk=flaw.pk)
        affect_in_memory = Affect.objects.get(pk=affect.pk)

        original_flaw_updated_dt = flaw_in_memory.updated_dt

        # Step 2: Simulate NVD collector updating Flaw at 18:03 (concurrent modification)
        with freeze_time("2024-03-06 18:03:00"):
            flaw_fresh = Flaw.objects.get(pk=flaw.pk)
            flaw_fresh.comment_zero = "Updated description with Thunderbird mentioned"
            flaw_fresh.save()  # This updates the DB with new updated_dt

            # Verify DB was updated
            flaw_from_db = Flaw.objects.get(pk=flaw.pk)
            assert flaw_from_db.updated_dt != original_flaw_updated_dt
            assert "Thunderbird" in flaw_from_db.comment_zero

        # Step 3: User saves Affect at 18:16 with stale Flaw still in memory
        with freeze_time("2024-03-06 18:16:00"):
            # Modify the affect (which triggers post_save signal)
            affect_in_memory.affectedness = Affect.AffectAffectedness.AFFECTED
            affect_in_memory.resolution = Affect.AffectResolution.DELEGATED  # Valid resolution for AFFECTED

            # The signal handler will try to save the stale flaw_in_memory
            # This SHOULD raise DataInconsistencyException because:
            # - flaw_in_memory.updated_dt is from 17:22
            # - DB has flaw with updated_dt from 18:03

            with pytest.raises(DataInconsistencyException) as exc_info:
                affect_in_memory.save()

            assert "outdated model instance" in str(exc_info.value).lower()

    @freeze_time("2024-03-06 17:22:00")
    def test_signal_detects_concurrent_flaw_modification_via_cvss_save(self):
        """
        Test that saving FlawCVSS with a stale parent Flaw raises DataInconsistencyException
        """
        # Step 1: Create Flaw and FlawCVSS
        flaw = FlawFactory(
            embargoed=False,
            comment_zero="Original CVSS description",
        )
        affect = AffectFactory(flaw=flaw)
        affect_cvss = AffectCVSSFactory(affect=affect)

        # Reload to simulate user's in-memory state
        affect_cvss_in_memory = affect.cvss_scores.first()

        original_flaw_updated_dt = flaw.updated_dt

        # Step 2: Concurrent Flaw modification
        with freeze_time("2024-03-06 18:03:00"):
            flaw_fresh = Flaw.objects.get(pk=flaw.pk)
            flaw_fresh.comment_zero = "Updated by collector"
            flaw_fresh.save()

            flaw_from_db = Flaw.objects.get(pk=flaw.pk)
            assert flaw_from_db.updated_dt != original_flaw_updated_dt

        # Step 3: User saves AffectCVSS (triggers signal that saves Flaw)
        with freeze_time("2024-03-06 18:16:00"):
            affect_cvss_in_memory.score = 7.5

            # Should detect that the Flaw was updated concurrently
            with pytest.raises(DataInconsistencyException):
                affect_cvss_in_memory.save()

    @freeze_time("2024-03-06 17:22:00")
    def test_signal_allows_save_when_no_concurrent_modification(self):
        """
        Test that signal handlers work normally when there's no concurrent modification
        """
        # Create Flaw and Affect
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(flaw=flaw)

        original_flaw_updated_dt = flaw.updated_dt

        # Save affect without any concurrent Flaw modification
        with freeze_time("2024-03-06 18:16:00"):
            affect.affectedness = Affect.AffectAffectedness.AFFECTED
            affect.resolution = Affect.AffectResolution.DELEGATED  # Valid resolution for AFFECTED

            # This should succeed - no concurrent modification
            affect.save()

            # Verify the signal updated the Flaw's updated_dt
            # Note: auto_timestamps=False in signal, so updated_dt should NOT change
            flaw_from_db = Flaw.objects.get(pk=flaw.pk)
            assert flaw_from_db.updated_dt == original_flaw_updated_dt

    @freeze_time("2024-03-06 17:22:00")
    def test_signal_works_after_refreshing_stale_flaw(self):
        """
        Test the recovery pattern: refresh from DB and retry
        """
        # Step 1: Create entities
        flaw = FlawFactory(embargoed=False, comment_zero="Original")
        affect = AffectFactory(flaw=flaw)

        # Reload to get in-memory copies
        affect_in_memory = Affect.objects.get(pk=affect.pk)

        # Step 2: Concurrent modification
        with freeze_time("2024-03-06 18:03:00"):
            flaw_fresh = Flaw.objects.get(pk=flaw.pk)
            flaw_fresh.comment_zero = "Updated by collector"
            flaw_fresh.save()

        # Step 3: First save attempt fails
        with freeze_time("2024-03-06 18:16:00"):
            affect_in_memory.affectedness = Affect.AffectAffectedness.AFFECTED
            affect_in_memory.resolution = Affect.AffectResolution.DELEGATED  # Valid resolution

            with pytest.raises(DataInconsistencyException):
                affect_in_memory.save()

            # Step 4: Refresh and retry (correct recovery pattern)
            affect_refreshed = Affect.objects.get(pk=affect.pk)
            affect_refreshed.affectedness = Affect.AffectAffectedness.AFFECTED
            affect_refreshed.resolution = Affect.AffectResolution.DELEGATED  # Valid resolution

            # This should succeed now
            affect_refreshed.save()

            # Verify it worked
            assert Affect.objects.get(pk=affect.pk).affectedness == Affect.AffectAffectedness.AFFECTED
