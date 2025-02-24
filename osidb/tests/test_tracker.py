"""
Tracker model related tests
"""

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone
from freezegun import freeze_time

from apps.taskman.service import TaskResolution
from osidb.models import Affect, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestTracker:
    @pytest.mark.parametrize(
        "flaw1_impact,flaw2_impact,affect1_impact,affect2_impact,expected_impact",
        [
            ("LOW", "MODERATE", "IMPORTANT", "CRITICAL", "CRITICAL"),
            ("LOW", "IMPORTANT", "MODERATE", "MODERATE", "MODERATE"),
            ("LOW", "IMPORTANT", "", "", "IMPORTANT"),
            ("LOW", "LOW", "", "LOW", "LOW"),
        ],
    )
    def test_aggregeted_impact(
        self,
        flaw1_impact,
        flaw2_impact,
        affect1_impact,
        affect2_impact,
        expected_impact,
    ):
        """
        test that the aggregated impact is properly computed
        """
        flaw1 = FlawFactory(impact=flaw1_impact)
        flaw2 = FlawFactory(embargoed=flaw1.embargoed, impact=flaw2_impact)

        affect1 = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            flaw=flaw1,
            impact=affect1_impact,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        affect2 = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            flaw=flaw2,
            impact=affect2_impact,
            ps_module=affect1.ps_module,
            ps_component=affect1.ps_component,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        ps_module = PsModuleFactory(name=affect1.ps_module)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        tracker = TrackerFactory(
            affects=[affect1, affect2],
            embargoed=flaw1.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )
        assert tracker.aggregated_impact == expected_impact

    @pytest.mark.enable_signals
    def test_last_impact_increase(self):
        """
        Test that the last impact increase date is correctly recorded in the tracker.
        """
        flaw1 = FlawFactory(embargoed=False)
        flaw2 = FlawFactory(embargoed=flaw1.embargoed)
        affect1 = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            flaw=flaw1,
            impact="LOW",
            resolution=Affect.AffectResolution.DELEGATED,
        )
        affect2 = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            flaw=flaw2,
            impact="LOW",
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=affect1.ps_module,
            ps_component=affect1.ps_component,
        )
        ps_module = PsModuleFactory(name=affect1.ps_module)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        tracker = TrackerFactory(
            affects=[affect1, affect2],
            embargoed=flaw1.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        # If it has never increased it should not contain a value
        assert tracker.last_impact_increase_dt is None

        modify_dt = timezone.datetime(2050, 10, 19)

        with freeze_time(modify_dt):
            affect1.impact = "MODERATE"
            affect1.save()

        # Get updated tracker instance
        tracker = Tracker.objects.get(uuid=tracker.uuid)
        assert tracker.last_impact_increase_dt == modify_dt.astimezone(
            timezone.get_current_timezone()
        )

        # If the aggregated impact doesn't increase, even if one of the
        # related affects increases its impact, do not modify the datetime
        old_modify_dt = modify_dt
        modify_dt = timezone.datetime(2050, 10, 23)
        with freeze_time(modify_dt):
            affect2.impact = "MODERATE"
            affect2.save()
        tracker = Tracker.objects.get(uuid=tracker.uuid)
        assert tracker.last_impact_increase_dt == old_modify_dt.astimezone(
            timezone.get_current_timezone()
        )

        # If the affects have no impact, it will use the flaw's impact
        flaw = FlawFactory(embargoed=False, impact="LOW")
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            flaw=flaw,
            impact="",
            resolution=Affect.AffectResolution.DELEGATED,
        )
        ps_module = PsModuleFactory(name=affect.ps_module)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )
        assert tracker.last_impact_increase_dt is None
        modify_dt = timezone.datetime(2050, 10, 23)
        with freeze_time(modify_dt):
            flaw.impact = "MODERATE"
            flaw.save()
        tracker = Tracker.objects.get(uuid=tracker.uuid)
        assert tracker.last_impact_increase_dt == modify_dt.astimezone(
            timezone.get_current_timezone()
        )

    def test_is_unacked(self):
        """
        test that (un)acked property works correctly
        """
        ps_module = PsModuleFactory()
        acked_ps_update_stream = PsUpdateStreamFactory(
            ps_module=ps_module,
            unacked_to_ps_module=None,
        )
        unacked_ps_update_stream = PsUpdateStreamFactory(
            ps_module=ps_module,
            unacked_to_ps_module=ps_module,
        )

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
        )

        acked_tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=acked_ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )
        unacked_tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=unacked_ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        assert acked_tracker.is_acked and not acked_tracker.is_unacked
        assert not unacked_tracker.is_acked and unacked_tracker.is_unacked

    def test_tracker_external_key_constraint(self):
        """
        test that multiple trackers can be created at the same time
        without external_system_id but two trackers can't have the
        same external_system_id after creation
        """
        ps_module = PsModuleFactory()
        stream1 = PsUpdateStreamFactory(ps_module=ps_module)
        stream2 = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
        )

        tracker1 = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=stream1.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            external_system_id="",
        )
        tracker2 = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=stream2.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            external_system_id="",
        )

        with pytest.raises(ValidationError):
            tracker1.external_system_id = "TEST-1"
            tracker1.save()
            tracker2.external_system_id = "TEST-1"
            tracker2.save()

    @pytest.mark.parametrize(
        "resolution1,resolution2,justification1,justification2,expected_justification",
        [
            (
                "Not a Bug",
                "Not a Bug",
                "Inline Mitigations already Exist",
                "Inline Mitigations already Exist",
                "Inline Mitigations already Exist",
            ),
            (
                "Not a Bug",
                "Not a Bug",
                "Inline Mitigations already Exist",
                "Vulnerable Code not Present",
                "Component not Present",
            ),
            ("Not a Bug", "Done", "Inline Mitigations already Exist", "", ""),
        ],
    )
    def test_delegated_not_affected_justifications(
        self,
        resolution1,
        resolution2,
        justification1,
        justification2,
        expected_justification,
    ):
        """
        Test that the delegated not affected justification for affects based on its trackers is
        correctly computed.
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        stream1 = PsUpdateStreamFactory(ps_module=ps_module)
        stream2 = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        TrackerFactory(
            affects=[affect],
            embargoed=flaw.embargoed,
            ps_update_stream=stream1.name,
            type=Tracker.TrackerType.JIRA,
            resolution=resolution1,
            not_affected_justification=justification1,
        )
        TrackerFactory(
            affects=[affect],
            embargoed=flaw.embargoed,
            ps_update_stream=stream2.name,
            type=Tracker.TrackerType.JIRA,
            resolution=resolution2,
            not_affected_justification=justification2,
        )
        assert affect.delegated_not_affected_justification == expected_justification


class TestTrackerValidators:
    def test_validate_good(self):
        """
        test that no validator complains about valid tracker
        """
        try:
            flaw = FlawFactory()
            ps_module = PsModuleFactory()
            affect = AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_module=ps_module.name,
            )
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            # do not raise here
            # validation is run on save
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.embargoed,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
                ps_update_stream=ps_update_stream.name,
            )
        except ValidationError:
            pytest.fail("Tracker creation should not fail here")

    def test_validate_no_affect(self):
        """
        test that creation of a tracker without an affect results in an exception
        """
        ps_update_stream = PsUpdateStreamFactory()

        with pytest.raises(
            ValidationError,
            match="Tracker must be associated with an affect",
        ):
            TrackerFactory(
                ps_update_stream=ps_update_stream.name,
            )

    def test_validate_no_ps_module(self):
        """
        test that creation of a tracker without a valid PS module results in an exception
        """
        flaw = FlawFactory()
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module="unknown",
        )
        ps_update_stream = PsUpdateStreamFactory()

        with pytest.raises(
            ValidationError,
            match="Tracker must be associated with a valid PS module",
        ):
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.embargoed,
                ps_update_stream=ps_update_stream.name,
            )

    def test_validate_no_ps_update_stream(self):
        """
        test that creation of a tracker without a valid PS update stream results in an exception
        """
        flaw = FlawFactory()
        ps_module = PsModuleFactory()
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
        )

        with pytest.raises(
            ValidationError,
            match="Tracker must be associated with a valid PS update stream",
        ):
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.embargoed,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
                ps_update_stream="unknown",
            )

    def test_validate_multi_flaw_tracker_ps_module(self):
        """
        test that a multi-flaw tracker is always associated
        with affects with the same PS module only
        """
        flaw1 = FlawFactory()
        flaw2 = FlawFactory()
        affect1 = AffectFactory(
            flaw=flaw1,
            ps_module="first",
            ps_component="component",
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            ps_module="second",
            ps_component="component",
        )
        with pytest.raises(
            ValidationError,
            match="Tracker must be associated only with affects with the same PS module",
        ):
            TrackerFactory(affects=[affect1, affect2])

    def test_validate_multi_flaw_tracker_ps_component(self):
        """
        test that a multi-flaw tracker is always associated
        with affects with the same PS component only
        """
        flaw1 = FlawFactory()
        flaw2 = FlawFactory()
        affect1 = AffectFactory(
            flaw=flaw1,
            ps_module="module",
            ps_component="firts",
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            ps_module="module",
            ps_component="second",
        )
        with pytest.raises(
            ValidationError,
            match="Tracker must be associated only with affects with the same PS component",
        ):
            TrackerFactory(affects=[affect1, affect2])

    @pytest.mark.parametrize(
        "bts,tracker_type,raises",
        [
            ("bugzilla", Tracker.TrackerType.BUGZILLA, False),
            ("bugzilla", Tracker.TrackerType.JIRA, True),
            ("jboss", Tracker.TrackerType.BUGZILLA, True),
            ("jboss", Tracker.TrackerType.JIRA, False),
        ],
    )
    def test_validate_tracker_bts_match(self, bts, tracker_type, raises):
        """
        test that the tracker type corresponds to its BTS
        """
        ps_module = PsModuleFactory(bts_name=bts)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.NEW, ps_module=ps_module.name
        )

        if raises:
            with pytest.raises(
                ValidationError,
                match="Tracker type and BTS mismatch:",
            ):
                TrackerFactory(
                    acl_read=affect.acl_read,
                    acl_write=affect.acl_write,
                    affects=[affect],
                    ps_update_stream=ps_update_stream.name,
                    type=tracker_type,
                )
        else:
            TrackerFactory(
                acl_read=affect.acl_read,
                acl_write=affect.acl_write,
                affects=[affect],
                ps_update_stream=ps_update_stream.name,
                type=tracker_type,
            )

    def test_validate_not_affected_justification(self):
        """
        Test that a Jira tracker closed as "Not a Bug" and no justification raises
        a validation error.
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
        )

        with pytest.raises(
            ValidationError,
        ):
            TrackerFactory(
                affects=[affect],
                embargoed=flaw.embargoed,
                type=Tracker.TrackerType.JIRA,
                ps_update_stream=ps_update_stream.name,
                resolution=TaskResolution.NOT_A_BUG,
                not_affected_justification="",
            )
