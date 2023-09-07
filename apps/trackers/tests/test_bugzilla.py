"""
Bugzilla specific tracker test cases
"""
import pytest

from apps.bbsync.constants import RHSCL_BTS_KEY
from apps.bbsync.exceptions import ProductDataError
from apps.bbsync.tests.factories import BugzillaComponentFactory, BugzillaProductFactory
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
                ps_module=ps_module.name,
                ps_component="component",
            )
            affects.append(affect)
            flaw_ids.append(str(affect.flaw.bz_id))

        tracker = TrackerFactory(
            affects=affects,
            embargoed=False,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "blocks" in query
        assert sorted(query["blocks"]) == sorted(flaw_ids)

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
            ps_module=ps_module.name,
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
            ps_module=ps_module.name,
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
            ps_module=ps_module.name,
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
            ps_module=ps_module.name,
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
            ps_module=ps_module.name,
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
            ps_module=ps_module.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
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
            ps_module=ps_module.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
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
            ps_module=ps_module.name,
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
            ps_module=ps_module.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        # create query
        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "keywords" in query
        assert "Security" in query["keywords"]
        assert "SecurityTracking" in query["keywords"]

        # update query
        query = TrackerBugzillaQueryBuilder(tracker, tracker).query

        assert "keywords" in query
        assert "add" in query["keywords"]
        assert "Security" in query["keywords"]["add"]
        assert "SecurityTracking" in query["keywords"]["add"]
