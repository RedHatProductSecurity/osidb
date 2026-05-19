from datetime import datetime, timedelta, timezone

import pytest

from osidb.models import Affect
from osidb.tasks import fix_acl_inconsistencies
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


@pytest.mark.django_db(transaction=True)
class TestFixACLInconsistencies:
    """Test cases for the fix_acl_inconsistencies periodic task"""

    def test_fix_affect_acl_mismatch(
        self,
        public_read_groups,
        public_write_groups,
        internal_read_groups,
        internal_write_groups,
    ):
        """Test that Affects get fixed when by scheduled task when having inconsistent ACL with Flaw"""
        # Create a Flaw with public ACLs
        unembargo_dt = datetime.now(timezone.utc) - timedelta(seconds=1)
        flaw = FlawFactory(
            acl_read=public_read_groups,
            acl_write=public_write_groups,
            unembargo_dt=unembargo_dt,
        )

        # Create an Affect with internal ACLs
        affect = AffectFactory(
            flaw=flaw,
            acl_read=internal_read_groups,
            acl_write=internal_write_groups,
        )

        assert affect.acl_read != flaw.acl_read
        assert affect.acl_write != flaw.acl_write

        result = fix_acl_inconsistencies()

        assert result["affects_fixed"] == 1
        assert result["trackers_fixed"] == 0
        assert result["trackers_skipped"] == 0

        affect.refresh_from_db()
        assert affect.acl_read == flaw.acl_read
        assert affect.acl_write == flaw.acl_write
        assert affect.acl_read == public_read_groups
        assert affect.acl_write == public_write_groups

    def test_fix_tracker_acl_with_single_flaw(
        self,
        public_read_groups,
        public_write_groups,
        internal_read_groups,
        internal_write_groups,
    ):
        """Test that Trackers get fixed when by scheduled task when having inconsistent ACL with Flaw"""
        # Create a Flaw with public ACLs
        unembargo_dt = datetime.now(timezone.utc) - timedelta(seconds=1)
        flaw = FlawFactory(
            acl_read=public_read_groups,
            acl_write=public_write_groups,
            unembargo_dt=unembargo_dt,
        )

        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            acl_read=public_read_groups,
            acl_write=public_write_groups,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        # Create a Tracker with internal ACLs
        tracker = TrackerFactory(
            type="JIRA",
            acl_read=internal_read_groups,
            acl_write=internal_write_groups,
            ps_update_stream=ps_update_stream.name,
            affects=[affect],
        )

        assert tracker.acl_read != flaw.acl_read
        assert tracker.acl_write != flaw.acl_write

        result = fix_acl_inconsistencies()

        assert result["affects_fixed"] == 0
        assert result["trackers_fixed"] == 1
        assert result["trackers_skipped"] == 0

        tracker.refresh_from_db()
        assert tracker.acl_read == flaw.acl_read
        assert tracker.acl_write == flaw.acl_write
        assert tracker.acl_read == public_read_groups
        assert tracker.acl_write == public_write_groups

    def test_skip_tracker_with_different_flaw_acls(
        self,
        public_read_groups,
        public_write_groups,
        internal_read_groups,
        internal_write_groups,
    ):
        """Test that Trackers are NOT changed when related Flaws have different ACLs"""
        # Create two Flaws with different ACLs
        unembargo_dt = datetime.now(timezone.utc) - timedelta(seconds=1)
        flaw1 = FlawFactory(
            acl_read=public_read_groups,
            acl_write=public_write_groups,
            unembargo_dt=unembargo_dt,
        )
        flaw2 = FlawFactory(
            acl_read=internal_read_groups,
            acl_write=internal_write_groups,
            unembargo_dt=unembargo_dt,
        )

        # Create a multi-flaw Tracker with internal ACLs
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect1 = AffectFactory(
            flaw=flaw1,
            ps_update_stream=ps_update_stream.name,
            ps_component="component1",
            acl_read=public_read_groups,
            acl_write=public_write_groups,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            ps_update_stream=ps_update_stream.name,
            ps_component="component1",
            acl_read=flaw2.acl_read,
            acl_write=flaw2.acl_write,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        # Create tracker with matching PS fields and JIRA type
        tracker = TrackerFactory(
            type="JIRA",
            acl_read=internal_read_groups,
            acl_write=internal_write_groups,
            ps_update_stream=ps_update_stream.name,
            affects=[affect1, affect2],
        )

        # Store original Tracker ACLs
        original_tracker_read = tracker.acl_read.copy()
        original_tracker_write = tracker.acl_write.copy()

        assert flaw1.acl_read != flaw2.acl_read
        assert flaw1.acl_write != flaw2.acl_write

        result = fix_acl_inconsistencies()

        assert result["affects_fixed"] == 0
        assert result["trackers_fixed"] == 0
        assert result["trackers_skipped"] == 1

        # Verify Tracker ACLs were NOT changed
        tracker.refresh_from_db()
        assert tracker.acl_read == original_tracker_read
        assert tracker.acl_write == original_tracker_write
        assert tracker.acl_read == internal_read_groups
        assert tracker.acl_write == internal_write_groups
