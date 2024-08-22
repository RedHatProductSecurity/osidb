import uuid

import pytest
from django.conf import settings
from django.utils import timezone

from apps.bbsync.query import FlawBugzillaQueryBuilder
from apps.workflows.workflow import WorkflowModel
from osidb.core import generate_acls
from osidb.models import Affect, Flaw, FlawComment, FlawSource, Snippet, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawCommentFactory,
    FlawFactory,
    PackageFactory,
    PackageVerFactory,
    PsModuleFactory,
    SnippetFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestGenerateBasics:
    @pytest.mark.parametrize(
        "components,cve_id,embargoed,title,summary",
        [
            (
                ["fat"],
                None,
                False,
                "hamster",
                "fat: hamster",
            ),
            (
                ["fat"],
                None,
                True,
                "hamster",
                "EMBARGOED fat: hamster",
            ),
            (
                ["fat"],
                "CVE-2000-12345",
                True,
                "hamster",
                "EMBARGOED CVE-2000-12345 fat: hamster",
            ),
            (
                ["fat"],
                "CVE-2000-12345",
                False,
                "hamster",
                "CVE-2000-12345 fat: hamster",
            ),
            (
                ["fat", "fluffy"],
                "CVE-2000-12345",
                False,
                "hamster",
                "CVE-2000-12345 fat: fluffy: hamster",
            ),
        ],
    )
    def test_generate_summary(self, components, cve_id, embargoed, title, summary):
        """
        test generating of summary
        """
        flaw = FlawFactory(
            components=components,
            cve_id=cve_id,
            embargoed=embargoed,
            title=title,
        )

        bbq = FlawBugzillaQueryBuilder(flaw)
        assert bbq.query["summary"] == summary

    @pytest.mark.parametrize(
        "cve_id1,cve_id2,embargoed,summary",
        [
            (
                "CVE-2000-12345",
                "CVE-2000-12346",
                False,
                "CVE-2000-12345 CVE-2000-12346 space: cucumber",
            ),
            (
                "CVE-2000-12346",
                "CVE-2000-12345",
                False,
                "CVE-2000-12345 CVE-2000-12346 space: cucumber",
            ),
            (
                "CVE-2000-12345",
                "CVE-2001-1234",
                False,
                "CVE-2000-12345 CVE-2001-1234 space: cucumber",
            ),
            (
                "CVE-2000-12345",
                "CVE-2000-1234",
                False,
                "CVE-2000-1234 CVE-2000-12345 space: cucumber",
            ),
            (
                "CVE-2000-99999",
                "CVE-2000-123456",
                False,
                "CVE-2000-99999 CVE-2000-123456 space: cucumber",
            ),
            (
                "CVE-2000-12345",
                "CVE-2000-12346",
                True,
                "EMBARGOED CVE-2000-12345 CVE-2000-12346 space: cucumber",
            ),
        ],
    )
    def test_generate_summary_multi_cve(self, cve_id1, cve_id2, embargoed, summary):
        """
        test generating of summary for multi-CVE Bugzilla flaw
        """
        component = "space"
        title = "cucumber"
        FlawFactory(
            components=[component],
            cve_id=cve_id1,
            embargoed=embargoed,
            title=title,
        )
        flaw = FlawFactory(
            components=[component],
            cve_id=cve_id2,
            embargoed=embargoed,
            title=title,
        )

        bbq = FlawBugzillaQueryBuilder(flaw)
        assert bbq.query["summary"] == summary

    def test_generate_summary_added_cve(self):
        """
        test generating of summary when assigning a new CVE
        OSIDB-902 reproducer
        """
        flaw = FlawFactory(
            components=["hammer"],
            cve_id="CVE-2000-1000",
            embargoed=False,
            title="is too heavy",
            meta_attr={"alias": "[]", "bz_id": "123"},
        )

        bbq = FlawBugzillaQueryBuilder(flaw)
        assert bbq.query["summary"] == "CVE-2000-1000 hammer: is too heavy"
        assert bbq.meta_attr["alias"] == '["CVE-2000-1000"]'

    def test_generate_summary_removed_cve(self):
        """
        test generating of summary when removing a CVE
        OSIDB-909 reproducer
        """
        flaw = FlawFactory(
            components=["hammer"],
            cve_id="",
            embargoed=False,
            title="is too heavy",
            meta_attr={"alias": '["CVE-2000-1000"]', "bz_id": "123"},
        )

        bbq = FlawBugzillaQueryBuilder(flaw)
        assert bbq.query["summary"] == "hammer: is too heavy"
        assert bbq.meta_attr["alias"] == "[]"

    @pytest.mark.parametrize(
        "workflow_state,result",
        [
            (WorkflowModel.WorkflowState.NOVALUE, "vulnerability"),
            (WorkflowModel.WorkflowState.NEW, "vulnerability-draft"),
            (WorkflowModel.WorkflowState.TRIAGE, "vulnerability"),
            (WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT, "vulnerability"),
            (WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT, "vulnerability"),
            (WorkflowModel.WorkflowState.DONE, "vulnerability"),
            (WorkflowModel.WorkflowState.REJECTED, "vulnerability-draft"),
        ],
    )
    @pytest.mark.parametrize("has_meta_attr", [True, False])
    def test_generate_component_before_bz_sync_or_with_draft_component(
        self, workflow_state, result, has_meta_attr
    ):
        """
        Test that component is set to "vulnerability-draft" in NEW and REJECTED
        workflow states and to "vulnerability" in other states when the flaw
        hasn't been synced to bugzilla yet or when its component was previously
        set to "vulnerability-draft".
        """
        if has_meta_attr:
            flaw = FlawFactory(
                workflow_state=workflow_state,
                meta_attr={"bz_id": "123", "bz_component": "vulnerability-draft"},
            )
        else:
            flaw = FlawFactory(
                workflow_state=workflow_state,
                meta_attr={},
            )

        bbq = FlawBugzillaQueryBuilder(flaw)
        assert bbq.query["component"] == result

    @pytest.mark.parametrize(
        "workflow_state",
        [
            WorkflowModel.WorkflowState.NOVALUE,
            WorkflowModel.WorkflowState.NEW,
            WorkflowModel.WorkflowState.TRIAGE,
            WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT,
            WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT,
            WorkflowModel.WorkflowState.DONE,
            WorkflowModel.WorkflowState.REJECTED,
        ],
    )
    def test_generate_component_after_bz_sync_with_regular_component(
        self, workflow_state
    ):
        """
        Test that component is set always to "vulnerability" in all workflow
        states when the flaw has been synced to bugzilla already with component
        previously set to "vulnerability".
        """
        flaw = FlawFactory(
            workflow_state=workflow_state,
            meta_attr={"bz_id": "123", "bz_component": "vulnerability"},
        )

        bbq = FlawBugzillaQueryBuilder(flaw)
        assert bbq.query["component"] == "vulnerability"

    def test_generate_alias_cve_id(self):
        """
        test generating of CVE ID alias on creation
        """
        flaw = FlawFactory(cve_id="CVE-2000-1001", meta_attr={})

        bbq = FlawBugzillaQueryBuilder(flaw)
        assert bbq.query["alias"] == ["CVE-2000-1001"]
        assert bbq.meta_attr["alias"] == '["CVE-2000-1001"]'

    def test_generate_alias_external_id(self):
        """
        test generating of external ID alias on creation
        """
        snippet = SnippetFactory(
            source=Snippet.Source.OSV, ext_id="GHSA-0001", cve_id=None
        )
        flaw = FlawFactory(cve_id=None, meta_attr={"external_ids": ["GHSA-0001"]})
        snippet.flaw = flaw
        snippet.save()

        bbq = FlawBugzillaQueryBuilder(flaw)
        assert bbq.query["alias"] == ["GHSA-0001"]
        assert bbq.meta_attr["alias"] == '["GHSA-0001"]'


class TestGenerateGroups:
    def test_create_public(self):
        """
        test that when creating a public flaw
        there are no or empty groups in BZ query
        """
        flaw = FlawFactory(embargoed=False, meta_attr={})
        FlawCommentFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw, affectedness=Affect.AffectAffectedness.NEW)
        ps_module = PsModuleFactory(
            name=affect.ps_module,
            bts_groups={
                "embargoed": [
                    "private",
                ]
            },
        )
        TrackerFactory(
            affects=[affect],
            embargoed=flaw.is_embargoed,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        bbq = FlawBugzillaQueryBuilder(flaw)
        query = bbq.query

        assert not query.get("groups", [])
        assert bbq.meta_attr["groups"] == "[]"

    def test_create_embargoed(self):
        """
        test that when creating an embargoed flaw
        there are expected groups in BZ query
        """
        flaw = FlawFactory(embargoed=True, meta_attr={})
        FlawCommentFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw, affectedness=Affect.AffectAffectedness.NEW)
        ps_module = PsModuleFactory(
            name=affect.ps_module,
            bts_groups={
                "embargoed": [
                    "private",
                ]
            },
        )
        TrackerFactory(
            affects=[affect],
            embargoed=flaw.is_embargoed,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        bbq = FlawBugzillaQueryBuilder(flaw)
        query = bbq.query

        groups = query.get("groups", [])
        assert len(groups) == 3
        assert "private" in groups
        assert "qe_staff" in groups
        assert "security" in groups
        assert bbq.meta_attr["groups"] == '["private", "qe_staff", "security"]'

    def test_create_embargoed_no_redhat(self):
        """
        test that when creating an embargoed flaw
        the redhat group is never being added
        """
        flaw = FlawFactory(embargoed=True)
        FlawCommentFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw, affectedness=Affect.AffectAffectedness.NEW)
        ps_module = PsModuleFactory(
            name=affect.ps_module,
            bts_groups={
                "embargoed": [
                    "redhat",
                ]
            },
        )
        TrackerFactory(
            affects=[affect],
            embargoed=flaw.is_embargoed,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        bbq = FlawBugzillaQueryBuilder(flaw)
        query = bbq.query

        groups = query.get("groups", [])
        assert "redhat" not in groups

    def test_unembargo(self):
        """
        test that unembargoeing flaw
        removes groups in BZ query
        """
        flaw = FlawFactory(
            embargoed=False,
            meta_attr={"groups": '["private", "qe_staff", "security"]', "bz_id": "1"},
        )
        FlawCommentFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw, affectedness=Affect.AffectAffectedness.NEW)
        ps_module = PsModuleFactory(
            name=affect.ps_module,
            bts_groups={
                "embargoed": [
                    "private",
                ]
            },
        )
        TrackerFactory(
            affects=[affect],
            embargoed=flaw.is_embargoed,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        bbq = FlawBugzillaQueryBuilder(flaw)
        query = bbq.query

        groups = query.get("groups", [])
        assert not groups.get("add")
        remove = groups.get("remove", [])
        assert len(remove) == 3
        assert "private" in remove
        assert "qe_staff" in remove
        assert "security" in remove
        assert bbq.meta_attr["groups"] == "[]"

    def test_affect_change(self):
        """
        test that affect change is properly reflected
        in added and removed groups in BZ query
        """
        flaw = FlawFactory(
            embargoed=True,
            meta_attr={"groups": '["private", "qe_staff", "security"]', "bz_id": "1"},
        )
        FlawCommentFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw, affectedness=Affect.AffectAffectedness.NEW)
        ps_module = PsModuleFactory(
            name=affect.ps_module,
            bts_groups={
                "embargoed": [
                    "secalert",
                ]
            },
        )
        TrackerFactory(
            affects=[affect],
            embargoed=flaw.is_embargoed,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        bbq = FlawBugzillaQueryBuilder(flaw)
        query = bbq.query

        groups = query.get("groups", [])
        assert ["secalert"] == groups.get("add", [])
        assert ["private"] == groups.get("remove", [])
        assert bbq.meta_attr["groups"] == '["qe_staff", "secalert", "security"]'

    def test_create_internal(self):
        """
        test that when creating an internal flaw
        there is only "redhat" group in BZ query
        """
        flaw = FlawFactory(
            acl_read=[
                uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_READ_GROUP])
            ],
            acl_write=[
                uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_WRITE_GROUP])
            ],
            embargoed=False,
            meta_attr={},
        )

        bbq = FlawBugzillaQueryBuilder(flaw)
        assert bbq.query["groups"] == ["redhat"]
        assert bbq.meta_attr["groups"] == '["redhat"]'


class TestGenerateComment:
    @pytest.mark.parametrize(
        "is_private",
        [
            (False),
            (True),
        ],
    )
    def test_generate_comment(self, is_private):
        """
        test generating a new comment
        """
        flaw = FlawFactory()
        FlawCommentFactory(
            flaw=flaw,
            text="Hello World",
            external_system_id="",
            synced_to_bz=False,
            created_dt=timezone.now(),
            updated_dt=timezone.now(),
            is_private=is_private,
        )
        orig_updated_dt = FlawComment.objects.get(external_system_id="").updated_dt
        assert FlawComment.objects.get(external_system_id="").synced_to_bz is False

        bbq = FlawBugzillaQueryBuilder(flaw)
        assert bbq.query["comment"] == {
            "body": "Hello World",
            "is_private": is_private,
        }
        assert FlawComment.objects.get(external_system_id="").synced_to_bz is True
        assert (
            FlawComment.objects.get(external_system_id="").updated_dt == orig_updated_dt
        )


class TestGenerateFlags:
    @pytest.mark.parametrize(
        "mi_state,hightouch,hightouch_lite,should_convert",
        [
            # flags to convert
            (Flaw.FlawMajorIncident.REQUESTED, "?", "?", True),
            (Flaw.FlawMajorIncident.REJECTED, "-", "-", True),
            (Flaw.FlawMajorIncident.APPROVED, "+", "-", True),
            (Flaw.FlawMajorIncident.CISA_APPROVED, "-", "+", True),
            # flags to ignore
            (Flaw.FlawMajorIncident.NOVALUE, None, None, False),
            (Flaw.FlawMajorIncident.INVALID, None, None, False),
        ],
    )
    def test_generate_hightouch_and_hightouch_lite(
        self, mi_state, hightouch, hightouch_lite, should_convert
    ):
        """
        Tests that major_incident_state is correctly converted into hightouch and
        hightouch-lite flags.
        Other flag-producing fields are set not to produce flags for ease of testing.
        """
        flaw = FlawFactory.build(
            major_incident_state=mi_state,
            requires_cve_description=Flaw.FlawRequiresCVEDescription.NOVALUE,
            nist_cvss_validation=Flaw.FlawNistCvssValidation.NOVALUE,
        )
        flaw.save(raise_validation_error=False)

        fbqb = FlawBugzillaQueryBuilder(flaw)
        flags = fbqb.query.get("flags")

        if should_convert:
            assert len(flags) == 2
            assert {"name": "hightouch", "status": hightouch} in flags
            assert {"name": "hightouch-lite", "status": hightouch_lite} in flags
        else:
            assert flags == []

    @pytest.mark.parametrize(
        "requires_cve_description,requires_doc_text,should_convert",
        [
            # flags to convert
            (Flaw.FlawRequiresCVEDescription.REQUESTED, "?", True),
            (Flaw.FlawRequiresCVEDescription.APPROVED, "+", True),
            (Flaw.FlawRequiresCVEDescription.REJECTED, "-", True),
            # a flag to ignore
            (Flaw.FlawRequiresCVEDescription.NOVALUE, None, False),
        ],
    )
    def test_generate_requires_doc_text(
        self, requires_cve_description, requires_doc_text, should_convert
    ):
        """
        Tests that requires_cve_description is correctly converted into requires_doc_text flag.
        Other flag-producing fields are set not to produce flags for ease of testing.
        """
        flaw = FlawFactory.build(
            requires_cve_description=requires_cve_description,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            nist_cvss_validation=Flaw.FlawNistCvssValidation.NOVALUE,
        )
        flaw.save(raise_validation_error=False)

        fbqb = FlawBugzillaQueryBuilder(flaw)
        flags = fbqb.query.get("flags")

        if should_convert:
            assert len(flags) == 1
            assert {"name": "requires_doc_text", "status": requires_doc_text} in flags
        else:
            assert flags == []

    @pytest.mark.parametrize(
        "field_state,flag_value,should_convert",
        [
            # flags to convert
            (Flaw.FlawNistCvssValidation.REQUESTED, "?", True),
            (Flaw.FlawNistCvssValidation.APPROVED, "+", True),
            (Flaw.FlawNistCvssValidation.REJECTED, "-", True),
            # flag to ignore
            (Flaw.FlawNistCvssValidation.NOVALUE, None, False),
        ],
    )
    def test_generate_nist_cvss_validation(
        self, field_state, flag_value, should_convert
    ):
        """
        Tests that nist_cvss_validation field is correctly converted into a flag.
        Other flag-producing fields are set not to produce flags for ease of testing.
        """
        flaw = FlawFactory.build(
            nist_cvss_validation=field_state,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            requires_cve_description=Flaw.FlawRequiresCVEDescription.NOVALUE,
        )
        flaw.save(raise_validation_error=False)

        fbqb = FlawBugzillaQueryBuilder(flaw)
        flags = fbqb.query.get("flags")

        if should_convert:
            assert len(flags) == 1
            assert {"name": "nist_cvss_validation", "status": flag_value} in flags
        else:
            assert flags == []


class TestGenerateFixedIn:
    def test_generate_fixed_in_without_meta_attr(self):
        """
        Tests that package_versions are not converted to fixed_in bz field when
        it's not clear where to use dash or space as separator.

        Test that nothing is generated when fixed_in is not present in meta_attr.
        This is so that existing historical fixed_in is not destroyed (there's
        a lot of non-package-version strings with dashes in old flaws).
        """
        flaw = FlawFactory(source=FlawSource.CUSTOMER)
        # fixed_in NOT in meta_attr!
        AffectFactory(flaw=flaw)

        pkg = PackageFactory(package="foobar", flaw=flaw)
        PackageVerFactory(version="1.2.3.4", package=pkg)

        fbqb = FlawBugzillaQueryBuilder(flaw)

        assert "cf_fixed_in" not in fbqb.query

    def test_generate_fixed_in(self):
        """
        Tests that package_versions are correctly converted to fixed_in bz field.

        Test that
        - Versions already in fixed_in are left in fixed_in as they are, including order and
          dash/space separator.
        - Versions no longer existing are removed from fixed_in.
        - New versions are added to fixed_in with space separator.
        """
        flaw = FlawFactory(source=FlawSource.CUSTOMER)
        flaw.meta_attr[
            "fixed_in"
        ] = "bazfoo-2.3.4.5, something 4.5, foobar 1.2.3.4, foobar-2.3.4.5"
        AffectFactory(flaw=flaw)

        pkg_a = PackageFactory(package="foobar", flaw=flaw)
        pkg_b = PackageFactory(package="bazfoo", flaw=flaw)
        pkg_c = PackageFactory(package="fobr", flaw=flaw)
        PackageVerFactory(version="1.2.3.4", package=pkg_a)
        PackageVerFactory(version="1.2.3.4", package=pkg_b)
        PackageVerFactory(version="2.3.4.5", package=pkg_a)
        PackageVerFactory(version="2.3.4.5", package=pkg_b)
        PackageVerFactory(version="3.4.5.6", package=pkg_c)

        fbqb = FlawBugzillaQueryBuilder(flaw)
        fixed_in = fbqb.query.get("cf_fixed_in")

        assert (
            fixed_in
            == "bazfoo-2.3.4.5, foobar 1.2.3.4, foobar-2.3.4.5, bazfoo 1.2.3.4, fobr 3.4.5.6"
        )
