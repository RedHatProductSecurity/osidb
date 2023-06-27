"""
Tracker model related tests
"""
import pytest
from django.core.exceptions import ValidationError

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
            ("LOW", "IMPORTANT", "MODERATE", "MODERATE", "IMPORTANT"),
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
            resolution=Affect.AffectResolution.FIX,
        )
        affect2 = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            flaw=flaw2,
            impact=affect2_impact,
            ps_module=affect1.ps_module,
            ps_component=affect1.ps_component,
            resolution=Affect.AffectResolution.FIX,
        )

        tracker = TrackerFactory(affects=[affect1, affect2], embargoed=flaw1.embargoed)
        assert tracker.aggregated_impact == expected_impact

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

        acked_tracker = TrackerFactory(ps_update_stream=acked_ps_update_stream.name)
        unacked_tracker = TrackerFactory(ps_update_stream=unacked_ps_update_stream.name)

        assert acked_tracker.is_acked and not acked_tracker.is_unacked
        assert not unacked_tracker.is_acked and unacked_tracker.is_unacked


class TestTrackerValidators:
    def test_validate_good(self):
        """
        test that no validator complains about valid tracker
        """
        # do not raise here
        # validation is run on save
        TrackerFactory()

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
                    type=tracker_type,
                )
        else:
            TrackerFactory(
                acl_read=affect.acl_read,
                acl_write=affect.acl_write,
                affects=[affect],
                type=tracker_type,
            )
