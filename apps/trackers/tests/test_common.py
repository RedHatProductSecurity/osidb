"""
tracker common functionality test cases
"""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from apps.sla.tests.test_framework import load_sla_policies
from apps.trackers.bugzilla.query import TrackerBugzillaQueryBuilder
from apps.trackers.common import TrackerQueryBuilder
from apps.trackers.jira.query import TrackerJiraQueryBuilder
from apps.trackers.models import JiraProjectFields
from osidb.models import Affect, Flaw, Impact, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsProductFactory,
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
            (None, False, Flaw.FlawMajorIncident.MINOR, "[Minor Incident] "),
            (None, False, Flaw.FlawMajorIncident.ZERO_DAY, "[0-day] "),
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


class TestTrackerQueryBuilderDescription:
    """
    TrackerQueryBuilder description related test cases
    """

    def test_bugzilla_basic(self):
        """
        test Bugzilla basic tracker description generation
        """
        ps_product = PsProductFactory(business_unit="Engineering")
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            name="special-module",
            private_trackers_allowed=True,
            ps_product=ps_product,
        )
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
            type=Tracker.TrackerType.BUGZILLA,
        )

        tqb = TrackerQueryBuilder()
        tqb.instance = tracker

        assert tqb.description == (
            "special-module tracking bug for large-component: see the bugs linked "
            'in the "Blocks" field of this bug for full details of the security issue(s).\n\n'
            "This bug is never intended to be made public, please put any public notes in the blocked bugs."
        )

    def test_bugzilla_embargoed(self):
        """
        test Bugzilla embargoed tracker description generation
        """
        ps_product = PsProductFactory(business_unit="Engineering")
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            name="special-module",
            private_trackers_allowed=True,
            ps_product=ps_product,
        )
        ps_update_stream = PsUpdateStreamFactory(
            name="deep-stream", ps_module=ps_module
        )
        flaw = FlawFactory(
            cve_id="CVE-2020-12345",
            embargoed=True,
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
            type=Tracker.TrackerType.BUGZILLA,
        )

        tqb = TrackerQueryBuilder()
        tqb.instance = tracker

        assert tqb.description == (
            "special-module tracking bug for large-component: see the bugs linked "
            'in the "Blocks" field of this bug for full details of the security issue(s).\n\n'
            "This bug is never intended to be made public, please put any public notes in the blocked bugs.\n\n"
            "NOTE THIS ISSUE IS CURRENTLY EMBARGOED, DO NOT MAKE PUBLIC COMMITS OR COMMENTS ABOUT THIS ISSUE.\n\n"
            'WARNING: NOTICE THAT REMOVING THE "SECURITY" GROUP FROM THIS TRACKER MAY BREAK THE EMBARGO.'
        )

    def test_bugzilla_rhel(self):
        """
        test Bugzilla RHEL tracker description generation
        """
        ps_module = PsModuleFactory(bts_name="bugzilla", name="rhel-42")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory()
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

        tqb = TrackerQueryBuilder()
        tqb.instance = tracker

        assert (
            "For the Enterprise Linux security issues handling process overview see:\n"
            "https://source.redhat.com/groups/public/product-security/content/product_security_wiki/eus_z_stream_and_security_bugs"
        ) in tqb.description

    @pytest.mark.parametrize("ps_component", ["xen", "kvm", "kernel-xen"])
    def test_bugzilla_virtualizaiton(self, ps_component):
        """
        test Bugzilla embargoed virtualization tracker description generation
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(embargoed=True)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            ps_component=ps_component,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        tqb = TrackerQueryBuilder()
        tqb.instance = tracker

        assert (
            "Information with regards to this bug is considered Red Hat Confidential "
            "until the embargo has lifted. Please post the patch only to the "
            "'rhkernel-team-list' and/or 'virt-devel' mailing lists for review and acks."
        ) in tqb.description

    @pytest.mark.parametrize("flaw_count", [1, 2, 3])
    def test_community(self, flaw_count):
        """
        test community tracker description generation
        """
        ps_product = PsProductFactory(business_unit="Community")
        ps_module = PsModuleFactory(ps_product=ps_product)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affects = []
        embargoed = None
        for idx in range(flaw_count):
            if embargoed is None:
                flaw = FlawFactory(bz_id=str(idx))
                embargoed = flaw.embargoed
            else:
                flaw = FlawFactory(
                    bz_id=str(idx),
                    embargoed=embargoed,
                )
            affects.append(
                AffectFactory(
                    flaw=flaw,
                    affectedness=Affect.AffectAffectedness.AFFECTED,
                    resolution=Affect.AffectResolution.DELEGATED,
                    ps_module=ps_module.name,
                    ps_component="large-component",
                    # created datetime defines the query result
                    # ordering which is later reflected in description
                    created_dt=datetime(2000 + idx, 1, 1, tzinfo=timezone.utc),
                )
            )

        tracker = TrackerFactory(
            affects=affects,
            embargoed=embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        tqb = TrackerQueryBuilder()
        tqb.instance = tracker

        if flaw_count == 1:
            assert tqb.description == (
                "More information about this security flaw is available in the following bug:\n\n"
                "https://bugzilla.redhat.com/show_bug.cgi?id=0\n\n"
                "Disclaimer: Community trackers are created by Red Hat Product Security team on a "
                "best effort basis. Package maintainers are required to ascertain if the flaw indeed "
                "affects their package, before starting the update process."
            )
        elif flaw_count == 2:
            assert tqb.description == (
                "More information about these security flaws is available in the following bugs:\n\n"
                "https://bugzilla.redhat.com/show_bug.cgi?id=0\n"
                "https://bugzilla.redhat.com/show_bug.cgi?id=1\n\n"
                "Disclaimer: Community trackers are created by Red Hat Product Security team on a "
                "best effort basis. Package maintainers are required to ascertain if the flaw indeed "
                "affects their package, before starting the update process."
            )
        elif flaw_count == 3:
            assert tqb.description == (
                (
                    "More information about these security flaws is available in the following bugs:\n\n"
                    "https://bugzilla.redhat.com/show_bug.cgi?id=0\n"
                    "https://bugzilla.redhat.com/show_bug.cgi?id=1\n"
                    "https://bugzilla.redhat.com/show_bug.cgi?id=2\n\n"
                    "Disclaimer: Community trackers are created by Red Hat Product Security team on a "
                    "best effort basis. Package maintainers are required to ascertain if the flaw indeed "
                    "affects their package, before starting the update process."
                )
            )

    def test_jira_basic(self):
        """
        test Jira basic tracker description generation
        """
        ps_product = PsProductFactory(business_unit="Engineering")
        ps_module = PsModuleFactory(
            bts_name="jboss",
            name="special-module",
            private_trackers_allowed=True,
            ps_product=ps_product,
        )
        ps_update_stream = PsUpdateStreamFactory(
            name="deep-stream", ps_module=ps_module
        )
        flaw = FlawFactory(
            bz_id="12345",
            cve_id="CVE-2020-12345",
            comment_zero="this flaw is very hard to fix",
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
            type=Tracker.TrackerType.JIRA,
        )

        tqb = TrackerQueryBuilder()
        tqb.instance = tracker

        assert tqb.description == (
            "Security Tracking Issue\n\n"
            "Do not make this issue public.\n\n"
            "Flaw:\n"
            "-----\n\n"
            "serious flaw\n"
            "https://bugzilla.redhat.com/show_bug.cgi?id=12345\n\n"
            "this flaw is very hard to fix\n\n"
            "~~~"
        )

    def test_jira_embargoed(self):
        """
        test Jira embargoed tracker description generation
        """
        ps_product = PsProductFactory(business_unit="Engineering")
        ps_module = PsModuleFactory(
            bts_name="jboss",
            name="special-module",
            private_trackers_allowed=True,
            ps_product=ps_product,
        )
        ps_update_stream = PsUpdateStreamFactory(
            name="deep-stream", ps_module=ps_module
        )
        flaw = FlawFactory(
            bz_id="12345",
            cve_id="CVE-2020-12345",
            comment_zero="this flaw is very hard to fix",
            embargoed=True,
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
            type=Tracker.TrackerType.JIRA,
        )

        tqb = TrackerQueryBuilder()
        tqb.instance = tracker

        assert tqb.description == (
            "Security Tracking Issue\n\n"
            "Do not make this issue public.\n\n"
            "NOTE THIS ISSUE IS CURRENTLY EMBARGOED, DO NOT MAKE PUBLIC COMMITS OR COMMENTS ABOUT THIS ISSUE.\n\n"
            'WARNING: NOTICE THAT CHANGING THE SECURITY LEVEL FROM "SECURITY ISSUE" TO "RED HAT INTERNAL" MAY BREAK THE EMBARGO.\n\n'
            "Flaw:\n"
            "-----\n\n"
            "serious flaw\n"
            "https://bugzilla.redhat.com/show_bug.cgi?id=12345\n\n"
            "this flaw is very hard to fix\n\n"
            "~~~"
        )

    @pytest.mark.parametrize("bts_name", ["bugzilla", "jboss"])
    @pytest.mark.parametrize("embargoed", [False, True])
    @pytest.mark.parametrize(
        "ps_component", ["kernel", "realtime-kernel", "kernel-rt", "kernel-alt"]
    )
    def test_kernel(self, bts_name, embargoed, ps_component):
        """
        test kernel tracker description generation
        """
        ps_module = PsModuleFactory(bts_name=bts_name)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(embargoed=embargoed)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            ps_component=ps_component,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        tqb = TrackerQueryBuilder()
        tqb.instance = tracker

        if bts_name == "bugzilla" and embargoed:
            assert (
                "Information with regards to this bug is considered Red Hat Confidential "
                "until the embargo has lifted. Please post the patch only to the "
                "'rhkernel-team-list' mailing list for review and acks."
            ) in tqb.description

        assert (
            "Reproducers, if any, will remain confidential and never be made public, unless done so by the security team."
            in tqb.description
        )

    @pytest.mark.parametrize("form_url", [None, "https://example.form.com"])
    def test_feedback_form(self, form_url):
        """
        test that tracker feedback form is included in the description if the env variable is set
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory()
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
            type=Tracker.TrackerType.JIRA,
        )

        with patch("apps.trackers.common.TRACKER_FEEDBACK_FORM_URL", form_url):
            tqb = TrackerQueryBuilder()
            tqb.instance = tracker

            if form_url is not None:
                assert form_url in tqb.description
            else:
                assert "feedback form" not in tqb.description

    @pytest.mark.parametrize("info_url", [None, "https://example.doc.com"])
    def test_vuln_mgmt_link(self, info_url):
        """
        test that the link to vunerability management documentation is included in the description
        if the env variable is set
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory()
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
            type=Tracker.TrackerType.JIRA,
        )

        with patch("apps.trackers.common.VULN_MGMT_INFO_URL", info_url):
            tqb = TrackerQueryBuilder()
            tqb.instance = tracker

            if info_url is not None:
                assert info_url in tqb.description
            else:
                assert (
                    "essential vulnerability management information"
                    not in tqb.description
                )

    def test_triage(self):
        """
        test triage tracker description generation
        """
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory()
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
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        tqb = TrackerQueryBuilder()
        tqb.instance = tracker

        assert "preliminary notification" not in tqb.description
        assert "triage" not in tqb.description
        assert "Triage" not in tqb.description


class TestTrackerQueryBuilderSLA:
    """
    TrackerQueryBuilder deadline/duedate and related stuff test cases
    """

    @pytest.mark.parametrize(
        "impact,under_sla",
        [
            (Impact.LOW, False),
            (Impact.MODERATE, False),
            (Impact.IMPORTANT, True),
            (Impact.CRITICAL, True),
        ],
    )
    def test_explicit_duedate(
        self,
        clean_policies,
        setup_vulnerability_issue_type_fields,
        impact,
        under_sla,
    ):
        """
        test that every tracker gets a deadline/duedate
        even if the value was empty because of no SLA
        """
        flaw = FlawFactory(
            embargoed=False,
            impact=impact,
            reported_dt=datetime(2020, 1, 1, tzinfo=timezone.utc),
            source="REDHAT",
        )

        # Bugzilla tracker context
        ps_module1 = PsModuleFactory(
            bts_key="BZPROJECT",
            bts_name="bugzilla",
        )
        affect1 = AffectFactory(
            flaw=flaw,
            impact=Impact.NOVALUE,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module1.name,
        )
        ps_update_stream1 = PsUpdateStreamFactory(ps_module=ps_module1)
        tracker1 = TrackerFactory(
            affects=[affect1],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream1.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        # Jira tracker context
        ps_module2 = PsModuleFactory(
            bts_key="FOOPROJECT",
            bts_name="jboss",
            private_trackers_allowed=False,
        )
        affect2 = AffectFactory(
            flaw=flaw,
            impact=Impact.NOVALUE,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module2.name,
        )
        ps_update_stream2 = PsUpdateStreamFactory(ps_module=ps_module2)
        tracker2 = TrackerFactory(
            affects=[affect2],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream2.name,
            type=Tracker.TrackerType.JIRA,
        )

        JiraProjectFields(
            project_key="FOOPROJECT",
            field_id="customfield_123",
            field_name="CVE Severity",
            allowed_values=[
                "Critical",
                "Important",
                "Moderate",
                "Low",
            ],
        ).save()
        target_start_id = "customfield_12313941"
        JiraProjectFields(
            project_key=ps_module2.bts_key,
            field_id=target_start_id,
            field_name="Target start",
        ).save()

        # simplified impact policies effective today
        sla_file = """
---
name: Critical
description: SLA policy applied to critical impact
conditions:
  affect:
    - aggregated impact is critical
sla:
  duration: 7
  start:
    latest:
      flaw:
        - unembargo date
  type: calendar days
---
name: Important
description: SLA policy applied to important impact
conditions:
  affect:
    - aggregated impact is important
sla:
  duration: 21
  start:
    latest:
      flaw:
        - unembargo date
  type: calendar days
"""

        load_sla_policies(sla_file)

        # check that the SLA fields are always in the query
        # but has a non-empty value only when SLA is applied

        query = TrackerBugzillaQueryBuilder(tracker1).query
        assert "deadline" in query
        assert bool(query["deadline"]) is under_sla

        query = TrackerJiraQueryBuilder(tracker2).query
        assert "duedate" in query["fields"]
        assert bool(query["fields"]["duedate"]) is under_sla
        assert target_start_id in query["fields"]
        assert bool(query["fields"][target_start_id]) is under_sla
