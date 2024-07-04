import json
import uuid

import pytest
from django.conf import settings
from django.utils import timezone
from django.utils.timezone import make_aware
from freezegun import freeze_time

from apps.bbsync.exceptions import SRTNotesValidationError
from apps.bbsync.query import FlawBugzillaQueryBuilder, SRTNotesBuilder
from apps.workflows.workflow import WorkflowModel
from osidb.core import generate_acls
from osidb.models import (
    Affect,
    AffectCVSS,
    Flaw,
    FlawComment,
    FlawCVSS,
    FlawSource,
    Impact,
    Snippet,
    Tracker,
)
from osidb.tests.factories import (
    AffectCVSSFactory,
    AffectFactory,
    FlawAcknowledgmentFactory,
    FlawCommentFactory,
    FlawCVSSFactory,
    FlawFactory,
    FlawReferenceFactory,
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
            cve_id="",
            embargoed=False,
            title="is too heavy",
        )
        old_flaw = Flaw.objects.first()
        flaw.cve_id = "CVE-2000-1000"

        bbq = FlawBugzillaQueryBuilder(flaw, old_flaw)
        assert bbq.query["summary"] == "CVE-2000-1000 hammer: is too heavy"

    def test_generate_summary_removed_cve(self):
        """
        test generating of summary when removing a CVE
        OSIDB-909 reproducer
        """
        flaw = FlawFactory(
            components=["hammer"],
            cve_id="CVE-2000-1000",
            embargoed=False,
            title="is too heavy",
        )
        old_flaw = Flaw.objects.first()
        flaw.cve_id = ""

        bbq = FlawBugzillaQueryBuilder(flaw, old_flaw)
        assert bbq.query["summary"] == "hammer: is too heavy"

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
        flaw = FlawFactory(cve_id="CVE-2000-1001")

        bbq = FlawBugzillaQueryBuilder(flaw)
        assert bbq.query["alias"] == ["CVE-2000-1001"]

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


class TestGenerateSRTNotes:
    @freeze_time(timezone.datetime(2022, 11, 25))
    def test_restore_original(self):
        """
        test that the original SRT notes attributes
        are preserved intact being known or unknown
        """
        srtnotes = """
        {
            "affects": [
                {
                    "affectedness": "affected",
                    "cvss2": null,
                    "cvss3": null,
                    "cvss4": null,
                    "impact": null,
                    "ps_component": "libssh",
                    "ps_module": "fedora-all",
                    "resolution": "delegated"
                }
            ],
            "impact": "moderate",
            "jira_trackers": [],
            "public": "2022-11-23",
            "reported": "2022-11-23",
            "source": "customer",
            "unknown": {
                "complex": "value",
                "array": []
            }
        }
        """
        flaw = FlawFactory(
            embargoed=False,
            impact=Impact.MODERATE,
            source=FlawSource.CUSTOMER,
            reported_dt=timezone.datetime(2022, 11, 23, tzinfo=timezone.utc),
            unembargo_dt=timezone.datetime(2022, 11, 23, tzinfo=timezone.utc),
            meta_attr={"original_srtnotes": srtnotes},
        )
        FlawCommentFactory(flaw=flaw)
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="libssh",
            ps_module="fedora-all",
            impact=Impact.NOVALUE,
        )
        old_flaw = FlawFactory(
            embargoed=False,
            reported_dt=timezone.datetime(2022, 11, 23, tzinfo=timezone.utc),
            unembargo_dt=timezone.datetime(2022, 11, 23, tzinfo=timezone.utc),
        )
        FlawCommentFactory(flaw=old_flaw)
        AffectFactory(flaw=old_flaw)

        bbq = FlawBugzillaQueryBuilder(flaw, old_flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        srtnotes_json = json.loads(srtnotes)
        for key in srtnotes_json.keys():
            assert cf_srtnotes_json[key] == srtnotes_json[key]

    def test_generate_acknowledgments(self):
        """
        test generating of SRT acknowledgments attribute array
        """
        flaw = FlawFactory(source=FlawSource.CUSTOMER)
        FlawCommentFactory(flaw=flaw)
        FlawAcknowledgmentFactory(
            flaw=flaw,
            affiliation="Acme Corp.",
            from_upstream=False,
            name="John Doe",
        )
        FlawAcknowledgmentFactory(
            flaw=flaw,
            affiliation="Acme Corp. Security Team",
            from_upstream=True,
            name="Canis latrans microdon",
        )

        bqb = FlawBugzillaQueryBuilder(flaw)
        cf_srtnotes = bqb.query.get("cf_srtnotes")
        cf_srtnotes_json = json.loads(cf_srtnotes)
        acknowledgments = cf_srtnotes_json.get("acknowledgments", [])
        assert len(acknowledgments) == 2

        for ack in acknowledgments:
            assert (
                ack["affiliation"] == "Acme Corp."
                and not ack["from_upstream"]
                and ack["name"] == "John Doe"
            ) or (
                ack["affiliation"] == "Acme Corp. Security Team"
                and ack["from_upstream"]
                and ack["name"] == "Canis latrans microdon"
            )

    @pytest.mark.enable_signals
    def test_generate_affects(self):
        """
        test generating of SRT affects attribute array
        """
        flaw = FlawFactory()
        FlawCommentFactory(flaw=flaw)
        affect = AffectFactory(
            flaw=flaw,
            ps_module="rhel-6",
            ps_component="ImageMagick",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=Impact.CRITICAL,
        )
        AffectFactory(
            flaw=flaw,
            ps_module="rhel-7",
            ps_component="kernel",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=Impact.MODERATE,
        )
        AffectFactory(
            flaw=flaw,
            ps_module="rhel-8",
            ps_component="bash",
            affectedness=Affect.AffectAffectedness.NOTAFFECTED,
            resolution=Affect.AffectResolution.NOVALUE,
            impact=Impact.NOVALUE,
        )
        AffectCVSSFactory(
            affect=affect,
            issuer=AffectCVSS.CVSSIssuer.REDHAT,
            version=AffectCVSS.CVSSVersion.VERSION2,
            vector="AV:N/AC:M/Au:N/C:P/I:P/A:P",  # 6.8
            comment="",
        )
        AffectCVSSFactory(
            affect=affect,
            issuer=AffectCVSS.CVSSIssuer.REDHAT,
            version=AffectCVSS.CVSSVersion.VERSION3,
            vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",  # 7.8
            comment="",
        )

        bbq = FlawBugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)
        assert "affects" in cf_srtnotes_json
        affects = cf_srtnotes_json["affects"]
        assert len(affects) == 3

        rhel6affect = rhel7affect = rhel8affect = None
        for affect in affects:
            if affect["ps_module"] == "rhel-6":
                rhel6affect = affect
            if affect["ps_module"] == "rhel-7":
                rhel7affect = affect
            if affect["ps_module"] == "rhel-8":
                rhel8affect = affect
        assert rhel6affect
        assert rhel7affect
        assert rhel8affect

        assert rhel6affect["ps_component"] == "ImageMagick"
        assert rhel6affect["affectedness"] == "affected"
        assert rhel6affect["resolution"] == "delegated"
        assert rhel6affect["impact"] == "critical"
        assert rhel6affect["cvss2"] == "6.8/AV:N/AC:M/Au:N/C:P/I:P/A:P"
        assert (
            rhel6affect["cvss3"] == "7.8/CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
        )

        assert rhel7affect["ps_component"] == "kernel"
        assert rhel7affect["affectedness"] == "affected"
        assert rhel7affect["resolution"] == "delegated"
        assert rhel7affect["impact"] == "moderate"
        assert rhel7affect["cvss2"] is None
        assert rhel7affect["cvss3"] is None

        assert rhel8affect["ps_component"] == "bash"
        assert rhel8affect["affectedness"] == "notaffected"
        assert rhel8affect["resolution"] is None
        assert rhel8affect["impact"] is None
        assert rhel8affect["cvss2"] is None
        assert rhel8affect["cvss3"] is None

    def test_generate_external_ids(self):
        """
        test generating of SRT external_ids attribute array
        """
        flaw = FlawFactory()
        snippet = SnippetFactory(source=Snippet.Source.NVD, flaw=flaw)

        bqb = FlawBugzillaQueryBuilder(flaw)
        cf_srtnotes = bqb.query.get("cf_srtnotes")
        cf_srtnotes_json = json.loads(cf_srtnotes)
        external_ids = cf_srtnotes_json.get("external_ids", [])
        assert external_ids == [snippet.external_id]

    def test_generate_references(self):
        """
        test generating of SRT references attribute array
        """
        flaw = FlawFactory()
        FlawReferenceFactory(
            flaw=flaw,
            type="EXTERNAL",
            url="https://httpd.apache.org/link123",
            description="link description",
        )

        bqb = FlawBugzillaQueryBuilder(flaw)
        cf_srtnotes = bqb.query.get("cf_srtnotes")
        cf_srtnotes_json = json.loads(cf_srtnotes)
        references = cf_srtnotes_json.get("references", [])

        assert len(references) == 1
        reference = references[0]
        assert reference["type"] == "external"
        assert reference["url"] == "https://httpd.apache.org/link123"
        assert reference["description"] == "link description"

    @pytest.mark.enable_signals
    def test_generate_flaw_cvss(self):
        """
        test generating of SRT notes CVSS attributes
        """
        flaw = FlawFactory()

        FlawCVSSFactory(
            flaw=flaw,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",  # 7.8
            version=FlawCVSS.CVSSVersion.VERSION3,
            comment="text",
        )
        # no CVSSv2

        bbq = FlawBugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        assert "cvss3" in cf_srtnotes_json
        assert (
            cf_srtnotes_json["cvss3"]
            == "7.8/CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
        )
        assert "cvss3_comment" in cf_srtnotes_json
        assert cf_srtnotes_json["cvss3_comment"] == "text"
        assert "cvss2" not in cf_srtnotes_json

    @pytest.mark.parametrize(
        "osidb_cwe,srtnotes,bz_present,bz_cwe",
        [
            (
                "CWE-123",
                """{"cwe": "CWE-123"}""",
                True,
                "CWE-123",
            ),
            (
                "CWE-555",
                """{"cwe": "CWE-123"}""",
                True,
                "CWE-555",
            ),
            (
                "",
                """{"cwe": "CWE-123"}""",
                True,
                None,
            ),
            (
                "CWE-555",
                "",
                True,
                "CWE-555",
            ),
            (
                "",
                "",
                False,
                None,
            ),
        ],
    )
    def test_cwe(self, osidb_cwe, srtnotes, bz_present, bz_cwe):
        """
        test generating of SRT notes CWE attribute
        """
        flaw = FlawFactory(cwe_id=osidb_cwe, meta_attr={"original_srtnotes": srtnotes})
        FlawCommentFactory(flaw=flaw)

        bbq = FlawBugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        if bz_present:
            assert "cwe" in cf_srtnotes_json
            assert cf_srtnotes_json["cwe"] == bz_cwe
        else:
            assert "cwe" not in cf_srtnotes_json

    @pytest.mark.parametrize(
        "osidb_impact,srtnotes,bz_present,bz_impact",
        [
            (
                Impact.LOW,
                """{"impact": "low"}""",
                True,
                "low",
            ),
            (
                Impact.MODERATE,
                """{"impact": "low"}""",
                True,
                "moderate",
            ),
            (
                Impact.IMPORTANT,
                "",
                True,
                "important",
            ),
            (
                Impact.CRITICAL,
                "{}",
                True,
                "critical",
            ),
            (
                Impact.NOVALUE,
                """{"impact": "critical"}""",
                True,
                "none",
            ),
            (
                Impact.NOVALUE,
                "",
                False,
                None,
            ),
        ],
    )
    def test_impact(self, osidb_impact, srtnotes, bz_present, bz_impact):
        """
        test generating of SRT notes impact attribute
        """
        flaw = FlawFactory.build(
            impact=osidb_impact, meta_attr={"original_srtnotes": srtnotes}
        )
        flaw.save(raise_validation_error=False)
        FlawCommentFactory(flaw=flaw)
        AffectFactory(flaw=flaw)

        bbq = FlawBugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        if bz_present:
            assert "impact" in cf_srtnotes_json
            assert cf_srtnotes_json["impact"] == bz_impact
        else:
            assert "impact" not in cf_srtnotes_json

    def test_jira_trackers_empty(self):
        """
        test generating SRT notes for with no Jira trackers
        """
        flaw = FlawFactory()
        FlawCommentFactory(flaw=flaw)
        AffectFactory(flaw=flaw)

        bbq = FlawBugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)
        assert "jira_trackers" not in cf_srtnotes_json

    def test_jira_trackers_preserved(self):
        """
        test that empty Jira trackers are preserved when
        there were some Jira trackers there originally
        """
        srtnotes = """{"jira_trackers": []}"""
        flaw = FlawFactory(meta_attr={"original_srtnotes": srtnotes})
        FlawCommentFactory(flaw=flaw)
        AffectFactory(flaw=flaw)

        bbq = FlawBugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)
        assert "jira_trackers" in cf_srtnotes_json
        assert cf_srtnotes_json["jira_trackers"] == []

    def test_jira_trackers_generate(self):
        """
        test that Jira tracker is added to SRT notes
        """
        flaw = FlawFactory()
        FlawCommentFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw, affectedness=Affect.AffectAffectedness.NEW)
        PsModuleFactory(
            bts_name="jboss",
            name=affect.ps_module,
        )
        TrackerFactory(
            affects=[affect],
            external_system_id="PROJECT-1",
            type=Tracker.TrackerType.JIRA,
            embargoed=flaw.is_embargoed,
        )

        bbq = FlawBugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)
        assert "jira_trackers" in cf_srtnotes_json
        assert cf_srtnotes_json["jira_trackers"] == [
            {"bts_name": "jboss", "key": "PROJECT-1"}
        ]

    @freeze_time(timezone.datetime(2022, 12, 30))
    @pytest.mark.parametrize("attribute_name", ["public", "reported"])
    @pytest.mark.parametrize(
        "new_dt,old_dt,old_date,new_date",
        [
            (
                timezone.datetime(2022, 12, 20),
                timezone.datetime(2022, 12, 20),
                "2022-12-20",
                "2022-12-20",
            ),
            (
                timezone.datetime(2022, 12, 20, 14),
                timezone.datetime(2022, 12, 20),
                "2022-12-20",
                "2022-12-20T14:00:00Z",
            ),
            (
                timezone.datetime(2022, 12, 20),
                timezone.datetime(2022, 12, 20),
                "2022-12-20T00:00:00Z",
                "2022-12-20T00:00:00Z",
            ),
        ],
    )
    def test_date_was_present(self, new_dt, old_dt, old_date, new_date, attribute_name):
        """
        test generating of SRT notes date attributes
        when it was present in the old SRT notes
        """
        flaw = FlawFactory(
            embargoed=False,
            meta_attr={
                "original_srtnotes": '{"' + attribute_name + '": "' + old_date + '"}'
            },
            reported_dt=make_aware(new_dt),
            unembargo_dt=make_aware(new_dt),
        )
        FlawCommentFactory(flaw=flaw)
        AffectFactory(flaw=flaw)

        old_flaw = FlawFactory(
            embargoed=False,
            reported_dt=make_aware(old_dt),
            unembargo_dt=make_aware(old_dt),
        )
        FlawCommentFactory(flaw=old_flaw)
        AffectFactory(flaw=old_flaw)

        bbq = FlawBugzillaQueryBuilder(flaw, old_flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        assert attribute_name in cf_srtnotes_json
        assert cf_srtnotes_json[attribute_name] == new_date

    @freeze_time(timezone.datetime(2022, 12, 30))
    @pytest.mark.parametrize("attribute_name", ["public", "reported"])
    @pytest.mark.parametrize(
        "date_obj,present,date_str",
        [
            (
                timezone.datetime(2022, 12, 20),
                True,
                "2022-12-20T00:00:00Z",
            ),
            (
                None,
                False,
                "",
            ),
        ],
    )
    def test_date_was_not_present(self, date_obj, present, date_str, attribute_name):
        """
        test generating of SRT notes date attributes
        when it was not present in the old SRT notes
        """
        flaw = FlawFactory.build(
            meta_attr={"original_srtnotes": ""},
            reported_dt=make_aware(date_obj) if date_obj else None,
            unembargo_dt=make_aware(date_obj) if date_obj else None,
        )
        # reported and unembargo dates have very different validations
        # but these are not the subject of this test so let us ignore them
        flaw.save(raise_validation_error=False)
        FlawCommentFactory(flaw=flaw)
        AffectFactory(flaw=flaw)

        old_flaw = FlawFactory.build(
            reported_dt=make_aware(date_obj) if date_obj else None,
            unembargo_dt=make_aware(date_obj) if date_obj else None,
        )
        # and here we ignore the validations too
        old_flaw.save(raise_validation_error=False)
        FlawCommentFactory(flaw=old_flaw)
        AffectFactory(flaw=old_flaw)

        bbq = FlawBugzillaQueryBuilder(flaw, old_flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        if present:
            assert attribute_name in cf_srtnotes_json
            assert cf_srtnotes_json[attribute_name] == date_str
        else:
            assert attribute_name not in cf_srtnotes_json

    @pytest.mark.parametrize(
        "osidb_source,srtnotes,bz_present,bz_source",
        [
            (
                FlawSource.CUSTOMER,
                """{"source": "customer"}""",
                True,
                "customer",
            ),
            (
                FlawSource.CUSTOMER,
                """{"source": "internet"}""",
                True,
                "customer",
            ),
            (
                FlawSource.HW_VENDOR,
                "",
                True,
                "hw-vendor",
            ),
            # this case should never be allowed by the validations
            # but let us consider it from the point of SRT notes builder
            (
                FlawSource.NOVALUE,
                """{"source": "internet"}""",
                True,
                None,
            ),
            (
                FlawSource.NOVALUE,
                "",
                False,
                None,
            ),
        ],
    )
    def test_source(self, osidb_source, srtnotes, bz_present, bz_source):
        """
        test generating of SRT notes source attribute
        """
        flaw = FlawFactory.build(
            embargoed=False,
            meta_attr={"original_srtnotes": srtnotes},
            source=osidb_source,
        )
        flaw.save(raise_validation_error=False)
        FlawCommentFactory(flaw=flaw)
        AffectFactory(flaw=flaw)

        bbq = FlawBugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        if bz_present:
            assert "source" in cf_srtnotes_json
            assert cf_srtnotes_json["source"] == bz_source
        else:
            assert "source" not in cf_srtnotes_json

    @pytest.mark.parametrize(
        "osidb_statement,srtnotes,bz_present,bz_statement",
        [
            (
                "some text",
                """{"statement": "some text"}""",
                True,
                "some text",
            ),
            (
                "other text",
                """{"statement": "some text"}""",
                True,
                "other text",
            ),
            (
                "",
                """{"statement": "some text"}""",
                True,
                None,
            ),
            (
                "",
                "",
                False,
                None,
            ),
        ],
    )
    def test_statement(self, osidb_statement, srtnotes, bz_present, bz_statement):
        """
        test generating of SRT notes statement attribute
        """
        flaw = FlawFactory(
            statement=osidb_statement, meta_attr={"original_srtnotes": srtnotes}
        )
        FlawCommentFactory(flaw=flaw)

        bbq = FlawBugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        if bz_present:
            assert "statement" in cf_srtnotes_json
            assert cf_srtnotes_json["statement"] == bz_statement
        else:
            assert "statement" not in cf_srtnotes_json

    def test_schema(self):
        """
        test complex flaw SRT notes generation
        to make sure that it is all according to the JSON schema
        """
        srtnotes = """
        {
            "acknowledgments": [
                {
                    "affiliation": "Acme Corp.",
                    "from_upstream": true,
                    "name": "Jane Doe"
                }
            ],
            "affects": [
                {
                    "affectedness": "affected",
                    "impact": "moderate",
                    "ps_component": "libssh",
                    "ps_module": "fedora-all",
                    "resolution": "delegated"
                }
            ],
            "cwe": "CWE-123",
            "impact": "moderate",
            "jira_trackers": [],
            "public": "2022-11-23",
            "reported": "2022-09-21",
            "source": "customer",
            "statement": "this flaw is funny",
            "unknown": {
                "complex": "value",
                "array": []
            }
        }
        """
        flaw = FlawFactory(
            cwe_id="CWE-123",
            embargoed=False,
            impact=Impact.IMPORTANT,
            meta_attr={"original_srtnotes": srtnotes},
            reported_dt=make_aware(timezone.datetime(2022, 9, 21)),
            source=FlawSource.CUSTOMER,
            statement="this flaw is very funny",
            unembargo_dt=make_aware(timezone.datetime(2021, 11, 23)),
        )
        FlawAcknowledgmentFactory(
            flaw=flaw,
            affiliation="Acme Corp.",
            from_upstream=True,
            name="Jane Doe",
        )
        FlawCommentFactory(flaw=flaw)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="libssh",
            ps_module="fedora-all",
            impact=Impact.MODERATE,
        )
        PsModuleFactory(
            bts_name="jboss",
            name="fedora-all",
        )
        TrackerFactory(
            affects=[affect],
            external_system_id="PROJECT-1",
            type=Tracker.TrackerType.JIRA,
        )

        bqb = FlawBugzillaQueryBuilder(flaw)
        # SRTNotesValidationError exception should not be raised here
        # This is the main part of this test.
        cf_srtnotes = bqb.query.get("cf_srtnotes")
        cf_srtnotes_json = json.loads(cf_srtnotes)
        assert cf_srtnotes and cf_srtnotes_json

        # Additionally, ensure that the validations were not run on empty data.
        assert cf_srtnotes_json["acknowledgments"][0]["affiliation"] == "Acme Corp."

    def test_invalid_schema(self):
        """
        test invalid flaw SRT notes data to make sure that the JSON schema validation works
        """
        srtnotes_builder = SRTNotesBuilder(None)
        # inject invalid JSON data
        srtnotes_builder._json = {"affects": None}

        with pytest.raises(
            SRTNotesValidationError, match="Invalid JSON produced for SRT notes"
        ):
            srtnotes_builder.validate()


class TestGenerateGroups:
    def test_create_public(self):
        """
        test that when creating a public flaw
        there are no or empty groups in BZ query
        """
        flaw = FlawFactory(embargoed=False)
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

    def test_create_embargoed(self):
        """
        test that when creating an embargoed flaw
        there are expected groups in BZ query
        """
        flaw = FlawFactory(embargoed=True)
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
            embargoed=True,
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

        new_flaw = Flaw.objects.first()
        new_flaw.acl_read = [
            uuid.UUID(acl) for acl in generate_acls([settings.PUBLIC_READ_GROUPS])
        ]  # make it unembargoed

        bbq = FlawBugzillaQueryBuilder(new_flaw, flaw)
        query = bbq.query

        groups = query.get("groups", [])
        assert not groups.get("add")
        remove = groups.get("remove", [])
        assert len(remove) == 3
        assert "private" in remove
        assert "qe_staff" in remove
        assert "security" in remove

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
        affect1 = AffectFactory(flaw=flaw, affectedness=Affect.AffectAffectedness.NEW)
        ps_module1 = PsModuleFactory(
            name=affect1.ps_module,
            bts_groups={
                "embargoed": [
                    "private",
                ]
            },
        )
        TrackerFactory(
            affects=[affect1],
            embargoed=flaw.is_embargoed,
            type=Tracker.BTS2TYPE[ps_module1.bts_name],
        )

        new_flaw = Flaw.objects.first()
        # remove existing affect
        new_flaw.affects.first().delete()
        # and add a newly created affect
        affect2 = AffectFactory(
            flaw=new_flaw, affectedness=Affect.AffectAffectedness.NEW
        )
        ps_module2 = PsModuleFactory(
            name=affect2.ps_module,
            bts_groups={
                "embargoed": [
                    "secalert",
                ]
            },
        )
        TrackerFactory(
            affects=[affect2],
            embargoed=new_flaw.is_embargoed,
            type=Tracker.BTS2TYPE[ps_module2.bts_name],
        )

        bbq = FlawBugzillaQueryBuilder(new_flaw, flaw)
        query = bbq.query

        groups = query.get("groups", [])
        assert ["secalert"] == groups.get("add", [])
        assert ["private"] == groups.get("remove", [])

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
        )

        bbq = FlawBugzillaQueryBuilder(flaw)
        assert bbq.query["groups"] == ["redhat"]


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
