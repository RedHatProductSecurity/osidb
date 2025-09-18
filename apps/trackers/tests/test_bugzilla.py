"""
Bugzilla specific tracker test cases
"""

import json

import pytest
from django.utils.timezone import datetime, make_aware

from apps.bbsync.constants import RHSCL_BTS_KEY
from apps.bbsync.exceptions import ProductDataError
from apps.bbsync.tests.factories import BugzillaComponentFactory, BugzillaProductFactory
from apps.sla.models import SLOPolicy
from apps.sla.tests.test_framework import load_policies
from apps.trackers.bugzilla.query import TrackerBugzillaQueryBuilder
from osidb.models import Affect, Impact, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)


class TestTrackerBugzillaQueryBuilder:
    """
    test Bugzilla tracker query building
    """

    @pytest.mark.parametrize("flaw_count", [1, 2, 3])
    def test_generate_blocks(self, flaw_count):
        """
        test that the query for the flaws to be blocked by the tracker is correctly generated
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affects, flaw_ids = [], []
        for idx in range(flaw_count):
            affect = AffectFactory(
                flaw__bz_id=idx,
                flaw__embargoed=False,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                ps_update_stream=ps_update_stream.name,
                ps_component="component",
            )
            affects.append(affect)
            flaw_ids.append(str(affect.flaw.bz_id))

        tracker = TrackerFactory(
            affects=affects,
            external_system_id=None,
            embargoed=False,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "blocks" in query
        assert sorted(query["blocks"]) == sorted(flaw_ids)

    @pytest.mark.parametrize("flaw_count", [1, 2, 3])
    def test_generate_whiteboard(self, flaw_count):
        """
        test that the tracker whiteboard contains all the related flaws
        this is especially needed for linking the non-Bugzilla flaws
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affects, flaw_uuids = [], []
        for idx in range(flaw_count):
            affect = AffectFactory(
                flaw__bz_id=f"{idx}",
                flaw__embargoed=False,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                ps_update_stream=ps_update_stream.name,
                ps_component="component",
            )
            affects.append(affect)
            flaw_uuids.append(str(affect.flaw.uuid))

        tracker = TrackerFactory(
            affects=affects,
            embargoed=False,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "whiteboard" in query
        whiteboard = json.loads(query["whiteboard"])
        assert "flaws" in whiteboard
        assert sorted(whiteboard["flaws"]) == sorted(flaw_uuids)

    def test_generate_deadline(self, clean_policies):
        """
        test that the tracker deadline query is properly generated
        """
        flaw = FlawFactory(
            embargoed=False,
            reported_dt=make_aware(datetime(2000, 1, 1)),
        )
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        slo_file = """
---
name: Not Embargoed
description: suitable for whatever we find on the street
conditions:
  flaw:
    - is not embargoed
slo:
  duration: 10
  start: reported date
  type: calendar days
"""

        load_policies(SLOPolicy, slo_file)
        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "deadline" in query
        assert query["deadline"] == "2000-01-11"

    @pytest.mark.parametrize(
        "ps_component,component_overrides,bz_component",
        [
            ("podman", {}, "podman"),
            ("container-tools:rhel8/podman", {}, "podman"),
            ("docker", {"docker": "podman"}, "podman"),
        ],
    )
    def test_generate_product_info(
        self, ps_component, component_overrides, bz_component
    ):
        """
        test that the product info query is correctly generated
        """
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            bts_key="Red Hat Enterprise Linux 9",
            component_overrides=component_overrides,
            default_component=None,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            ps_update_stream=ps_update_stream.name,
            ps_component=ps_component,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "product" in query
        assert query["product"] == ps_module.bts_key
        assert "component" in query
        assert query["component"] == bz_component  # this is what we mainly test here
        assert "sub_components" not in query
        assert "version" in query
        assert query["version"] == ps_update_stream.version

    @pytest.mark.parametrize(
        "ps_component,collections,bz_component,version",
        [
            ("podman", [], "podman", "unspecified"),
            ("podman", ["docker"], "podman", "unspecified"),
            ("podman", ["podman"], "podman", "podman"),
            ("podman-installer", ["podman"], "installer", "podman"),
        ],
    )
    def test_generate_product_info_rhscl(
        self, ps_component, collections, bz_component, version
    ):
        """
        test that the product info query is correctly generated for RHSCL
        """
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            bts_key=RHSCL_BTS_KEY,
            component_overrides={},
            default_component=None,
        )
        ps_update_stream = PsUpdateStreamFactory(
            collections=collections,
            ps_module=ps_module,
            version="default",
        )

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            ps_update_stream=ps_update_stream.name,
            ps_component=ps_component,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "product" in query
        assert query["product"] == ps_module.bts_key
        assert "component" in query
        assert query["component"] == bz_component  # this is what we mainly test here
        assert "sub_components" not in query
        assert "version" in query
        assert query["version"] == version

    @pytest.mark.parametrize(
        "exists,expected_component",
        [
            (True, "original-component"),
            (False, "default-component"),
        ],
    )
    def test_override_component_with_default(self, exists, expected_component):
        """
        test that the component in the Bugzilla query is overriden
        when not existing in Bugzilla and the default is defined
        """
        if exists:
            product = BugzillaProductFactory(name="Red Hat Enterprise Linux 9")
            BugzillaComponentFactory(name="original-component", product=product)

        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            bts_key="Red Hat Enterprise Linux 9",
            component_overrides={},
            default_component="default-component",
        )
        ps_update_stream = PsUpdateStreamFactory(
            collections=[],
            ps_module=ps_module,
            version="default-version",
        )

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            ps_update_stream=ps_update_stream.name,
            ps_component="original-component",
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "product" in query
        assert query["product"] == ps_module.bts_key
        assert "component" in query
        assert query["component"] == expected_component
        assert "sub_components" not in query
        assert "version" in query
        assert query["version"] == "default-version"

    def test_override_subcomponent_with_default(self):
        """
        test that the subcomponent in the Bugzilla query is overriden
        when not existing in Bugzilla and the default is defined
        """
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            bts_key="Red Hat Enterprise Linux 9",
            component_overrides={
                "podman": {
                    "component": "manager",
                    "sub_component": "installer",
                }
            },
            default_component=None,
        )
        ps_update_stream = PsUpdateStreamFactory(
            collections=[],
            ps_module=ps_module,
            version="version",
        )

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            ps_update_stream=ps_update_stream.name,
            ps_component="podman",
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "product" in query
        assert query["product"] == ps_module.bts_key
        assert "component" in query
        assert query["component"] == "manager"
        assert "sub_components" in query
        assert query["sub_components"] == {"manager": ["installer"]}
        assert "version" in query
        assert query["version"] == "version"

    @pytest.mark.parametrize(
        "impact,priority_severity",
        [
            (Impact.LOW, "low"),
            (Impact.MODERATE, "medium"),
            (Impact.IMPORTANT, "high"),
            (Impact.CRITICAL, "urgent"),
        ],
    )
    def test_generate_priority_severity(self, impact, priority_severity):
        """
        test that priority and severity fields are correctly set
        """
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
        )
        ps_update_stream = PsUpdateStreamFactory(
            ps_module=ps_module,
        )

        flaw = FlawFactory(impact=impact)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=None,  # no override here
            ps_update_stream=ps_update_stream.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "priority" in query
        assert query["priority"] == priority_severity
        assert "severity" in query
        assert query["severity"] == priority_severity

    @pytest.mark.parametrize(
        "bts_groups,groups",
        [
            ({"public": [], "embargoed": ["security"]}, []),
            ({"public": ["redhat"], "embargoed": []}, ["redhat"]),
            ({"public": ["redhat", "fedora"], "embargoed": []}, ["redhat", "fedora"]),
            ({"public": ["redhat"], "embargoed": ["fedora"]}, ["redhat"]),
        ],
    )
    def test_generate_groups_public(self, bts_groups, groups):
        """
        test that the groups are set correctly for a public tracker
        """
        ps_module = PsModuleFactory(
            bts_groups=bts_groups,
            bts_name="bugzilla",
        )
        ps_update_stream = PsUpdateStreamFactory(
            ps_module=ps_module,
        )

        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            external_system_id=None,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "groups" in query
        assert query["groups"] == groups

    @pytest.mark.parametrize(
        "bts_groups,groups",
        [
            ({"public": [], "embargoed": ["security"]}, ["security"]),
            ({"public": ["redhat"], "embargoed": ["security"]}, ["security"]),
            (
                {"public": ["redhat"], "embargoed": ["security", "top-secret"]},
                ["security", "top-secret"],
            ),
        ],
    )
    def test_generate_groups_embargoed(self, bts_groups, groups):
        """
        test that the groups are set correctly for an embargoed tracker
        """
        ps_module = PsModuleFactory(
            bts_groups=bts_groups,
            bts_name="bugzilla",
        )
        ps_update_stream = PsUpdateStreamFactory(
            ps_module=ps_module,
        )

        flaw = FlawFactory(embargoed=True)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            external_system_id=None,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "groups" in query
        assert query["groups"] == groups

    def test_generate_groups_embargoed_empty(self):
        """
        test that the embargoed tracker cannot be created with no Bugzilla groups
        """
        ps_module = PsModuleFactory(
            bts_groups={"public": [], "embargoed": []},
            bts_name="bugzilla",
        )
        ps_update_stream = PsUpdateStreamFactory(
            ps_module=ps_module,
        )

        flaw = FlawFactory(embargoed=True)
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
            type=Tracker.TrackerType.BUGZILLA,
        )

        with pytest.raises(
            ProductDataError,
            match="Cannot create EMBARGOED trackers without group restrictions!",
        ):
            TrackerBugzillaQueryBuilder(tracker).query

    def test_generate_keywords(self):
        """
        test that the expected keywords are in the query
        """
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
        )
        ps_update_stream = PsUpdateStreamFactory(
            ps_module=ps_module,
        )

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            external_system_id=None,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        # create query
        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "keywords" in query
        assert "Security" in query["keywords"]
        assert "SecurityTracking" in query["keywords"]

        # update query
        tracker.external_system_id = "123"
        tracker.save()
        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "keywords" in query
        assert "add" in query["keywords"]
        assert "Security" in query["keywords"]["add"]
        assert "SecurityTracking" in query["keywords"]["add"]

    @pytest.mark.parametrize(
        "component_cc, private_tracker_cc, default_cc, component, exists",
        [
            (True, True, True, "component", True),
            (True, True, True, "component", False),
            (True, True, True, "foobar", False),
            (True, False, False, "component", False),
            (False, True, False, "component", False),
            (False, False, True, "component", False),
        ],
    )
    def test_generate_cc(
        self, component_cc, private_tracker_cc, default_cc, component, exists
    ):
        """
        Test that CC lists are generated for a new tracker
        """

        # For brevity of pytest.mark.parametrize's arguments
        if component_cc:
            component_cc = {"component": ["a@redhat.com", "a2", "ee"]}
        else:
            component_cc = {}
        if private_tracker_cc:
            private_tracker_cc = ["b@redhat.com", "b2", "ee"]
        else:
            private_tracker_cc = []
        if default_cc:
            default_cc = ["c@redhat.com", "c2", "ee"]
        else:
            default_cc = []
        if exists:
            external_system_id = "1234"
        else:
            external_system_id = ""

        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            component_cc=component_cc,
            private_tracker_cc=private_tracker_cc,
            default_cc=default_cc,
        )
        ps_update_stream = PsUpdateStreamFactory(
            ps_module=ps_module,
        )
        flaw = FlawFactory()
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            ps_component=component,
        )
        tracker = TrackerFactory(
            affects=[affect],
            type=Tracker.TrackerType.BUGZILLA,
            ps_update_stream=ps_update_stream.name,
            external_system_id=external_system_id,
            embargoed=flaw.embargoed,
        )

        # create query
        query = TrackerBugzillaQueryBuilder(tracker).query

        if exists:
            assert "cc" not in query
        else:
            if component == "component":
                expected_component_cc = component_cc.get("component", [])
            else:
                # If the PS module's component is not listed in product definition's component_cc,
                # there is no match.
                expected_component_cc = []

            if tracker.embargoed:
                expected_private_tracker_cc = private_tracker_cc
            else:
                expected_private_tracker_cc = []

            # Unlike Jira, for BZ all names must be converted to emails
            expected_cc = sorted(
                set(
                    f"{n}@redhat.com" if "@" not in n else n
                    for n in (
                        expected_component_cc + expected_private_tracker_cc + default_cc
                    )
                )
            )

            if flaw.embargoed and not ps_module.private_trackers_allowed:
                expected_cc = []

            if expected_cc:
                assert sorted(query["cc"]) == expected_cc
            else:
                assert "cc" not in query
