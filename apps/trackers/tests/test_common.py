"""
tracker common functionality test cases
"""
import pytest

from apps.trackers.common import TrackerQueryBuilder
from osidb.models import Affect, Flaw, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)


class TestTrackerQueryBuilderSummary:
    """
    TrackerQueryBuilder summary related test cases
    """

    def test_basic(self):
        """
        test basic tracker summary generation
        """
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(
            name="deep-stream", ps_module=ps_module
        )
        flaw = FlawFactory(
            cve_id="CVE-2020-12345",
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="serious flaw",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            ps_component="large-component",
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        tqb = TrackerQueryBuilder()
        tqb.instance = tracker

        assert (
            tqb.summary == "CVE-2020-12345 large-component: serious flaw [deep-stream]"
        )

    @pytest.mark.parametrize(
        "cves,summary_cves",
        [
            ([None, None], ""),  # no CVEs
            ([None, "CVE-2000-1234"], "CVE-2000-1234 "),
            (["CVE-2000-11111", "CVE-2000-1234"], "CVE-2000-1234 CVE-2000-11111 "),
            (
                ["CVE-2003-1111", "CVE-2002-2222", "CVE-2001-3333"],
                "CVE-2001-3333 CVE-2002-2222 CVE-2003-1111 ",
            ),
            (
                ["CVE-2003-1111", "CVE-2002-2222", "CVE-2001-3333", None],
                "CVE-2001-3333 CVE-2002-2222 CVE-2003-1111 ",
            ),
            # too many CVEs to fit in the summary should be trimmed
            (
                [
                    "CVE-2000-11111",
                    "CVE-2000-11112",
                    "CVE-2000-11113",
                    "CVE-2000-11114",
                    "CVE-2000-11115",
                    "CVE-2000-11116",
                    "CVE-2000-11117",
                    "CVE-2000-11118",
                    "CVE-2000-11119",
                    "CVE-2000-11120",
                    "CVE-2000-11121",
                    "CVE-2000-11122",
                    "CVE-2000-11123",
                    "CVE-2000-11124",
                    "CVE-2000-11125",
                    "CVE-2000-11126",
                    "CVE-2000-11127",
                    "CVE-2000-11128",
                    "CVE-2000-11129",
                    "CVE-2000-11130",
                ],
                "CVE-2000-11111 CVE-2000-11112 CVE-2000-11113 CVE-2000-11114 "
                "CVE-2000-11115 CVE-2000-11116 CVE-2000-11117 CVE-2000-11118 CVE-2000-11119 "
                "CVE-2000-11120 CVE-2000-11121 CVE-2000-11122 CVE-2000-11123 ... ",
            ),
        ],
    )
    def test_multiple_flaws(self, cves, summary_cves):
        """
        test tracker with multiple flaws summary generation
        """
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(
            name="deep-stream", ps_module=ps_module
        )

        affects = []
        for cve in cves:
            flaw = FlawFactory(
                cve_id=cve,
                embargoed=False,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            )
            affects.append(
                AffectFactory(
                    flaw=flaw,
                    affectedness=Affect.AffectAffectedness.AFFECTED,
                    resolution=Affect.AffectResolution.DELEGATED,
                    ps_module=ps_module.name,
                    ps_component="large-component",
                )
            )

        tracker = TrackerFactory(
            affects=affects,
            embargoed=False,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        tqb = TrackerQueryBuilder()
        tqb.instance = tracker

        assert (
            tqb.summary == summary_cves + "large-component: various flaws [deep-stream]"
        )

    def test_description_too_long(self):
        """
        test tracker summary generation when the description is too long
        """
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(
            name="deep-stream", ps_module=ps_module
        )
        flaw = FlawFactory(
            cve_id="CVE-2020-12345",
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="Lorem ipsum dolor sit amet, consectetur "
            "adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore "
            "magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco "
            "laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor "
            "in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla "
            "pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa "
            "qui officia deserunt mollit anim id est laborum.",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            ps_component="large-component",
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        tqb = TrackerQueryBuilder()
        tqb.instance = tracker

        assert (
            tqb.summary
            == "CVE-2020-12345 large-component: Lorem ipsum dolor sit amet, "
            "consectetur adipiscing elit, sed do eiusmod tempor incididunt ut "
            "labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud "
            "exercitation ullamco laboris nisi ut aliqui ... [deep-stream]"
        )

    @pytest.mark.parametrize(
        "cve_id,embargoed,major_incident_state,summary_prefix",
        [
            (None, False, Flaw.FlawMajorIncident.NOVALUE, ""),
            (
                "CVE-2000-1234",
                False,
                Flaw.FlawMajorIncident.REQUESTED,
                "CVE-2000-1234 ",
            ),
            (None, True, Flaw.FlawMajorIncident.REJECTED, "EMBARGOED "),
            (
                "CVE-2000-1234",
                True,
                Flaw.FlawMajorIncident.NOVALUE,
                "EMBARGOED CVE-2000-1234 ",
            ),
            (None, False, Flaw.FlawMajorIncident.APPROVED, "[Major Incident] "),
            (
                "CVE-2000-1234",
                False,
                Flaw.FlawMajorIncident.APPROVED,
                "[Major Incident] CVE-2000-1234 ",
            ),
            (
                None,
                True,
                Flaw.FlawMajorIncident.APPROVED,
                "EMBARGOED [Major Incident] ",
            ),
            (
                "CVE-2000-1234",
                True,
                Flaw.FlawMajorIncident.APPROVED,
                "EMBARGOED [Major Incident] CVE-2000-1234 ",
            ),
            (
                None,
                False,
                Flaw.FlawMajorIncident.CISA_APPROVED,
                "[CISA Major Incident] ",
            ),
            (
                "CVE-2000-1234",
                False,
                Flaw.FlawMajorIncident.CISA_APPROVED,
                "[CISA Major Incident] CVE-2000-1234 ",
            ),
            (
                None,
                True,
                Flaw.FlawMajorIncident.CISA_APPROVED,
                "EMBARGOED [CISA Major Incident] ",
            ),
            (
                "CVE-2000-1234",
                True,
                Flaw.FlawMajorIncident.CISA_APPROVED,
                "EMBARGOED [CISA Major Incident] CVE-2000-1234 ",
            ),
        ],
    )
    def test_prefixes(self, cve_id, embargoed, major_incident_state, summary_prefix):
        """
        test tracker summary prefix generation
        """
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(
            name="deep-stream", ps_module=ps_module
        )
        flaw = FlawFactory(
            cve_id=cve_id,
            embargoed=embargoed,
            major_incident_state=major_incident_state,
            title="serious flaw",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            ps_component="large-component",
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        tqb = TrackerQueryBuilder()
        tqb.instance = tracker

        assert (
            tqb.summary
            == summary_prefix + "large-component: serious flaw [deep-stream]"
        )
