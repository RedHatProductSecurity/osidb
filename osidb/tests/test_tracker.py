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
    TrackerFactory,
)

pytestmark = pytest.mark.unit


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
