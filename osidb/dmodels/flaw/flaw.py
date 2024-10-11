import json
import logging
import re
import uuid
from datetime import datetime
from decimal import Decimal

import pghistory
from django.contrib.postgres import fields
from django.contrib.postgres.indexes import GinIndex
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import models
from django.db.models import Q
from django.utils import timezone
from psqlextra.fields import HStoreField

from apps.bbsync.constants import SYNC_FLAWS_TO_BZ, SYNC_FLAWS_TO_BZ_ASYNCHRONOUSLY
from apps.bbsync.mixins import BugzillaSyncMixin
from apps.taskman.constants import JIRA_TASKMAN_AUTO_SYNC_FLAW, SYNC_REQUIRED_FIELDS
from apps.taskman.mixins import JiraTaskSyncMixin
from apps.workflows.workflow import WorkflowFramework, WorkflowModel
from collectors.bzimport.constants import FLAW_PLACEHOLDER_KEYWORD
from osidb.constants import CVSS3_SEVERITY_SCALE, OSIDB_API_VERSION
from osidb.dmodels import FlawSource, Impact, PsModule, SpecialConsiderationPackage
from osidb.mixins import (
    ACLMixin,
    ACLMixinManager,
    Alert,
    AlertMixin,
    NullStrFieldsMixin,
    TrackingMixin,
    TrackingMixinManager,
)
from osidb.sync_manager import (
    BZSyncManager,
    FlawDownloadManager,
    JiraTaskDownloadManager,
)
from osidb.validators import no_future_date, validate_cve_id, validate_cwe_id

logger = logging.getLogger(__name__)


class FlawManager(ACLMixinManager, TrackingMixinManager):
    """flaw manager"""

    @staticmethod
    def create_flaw(bz_id, full_match=False, **extra_fields):
        """
        return a new flaw or update an existing flaw without saving
        this is meant for cases when UUID is not available - collector

        full match means that we match on both Bugzilla and CVE ID
        """
        try:
            cve_id = extra_fields.get("cve_id")
            if full_match:
                flaw = Flaw.objects.get(cve_id=cve_id, meta_attr__bz_id=bz_id)
            else:
                # flaws are primarily identified by Bugzilla ID
                # as it is constant while the CVE ID may change
                # however we eventually try both as if the source
                # is multi-CVE flaw the Bugzilla ID is not unique
                flaws = Flaw.objects.filter(meta_attr__bz_id=bz_id)
                flaw = flaws.get() if flaws.count() == 1 else flaws.get(cve_id=cve_id)

            for attr, value in extra_fields.items():
                setattr(flaw, attr, value)
            return flaw
        except ObjectDoesNotExist:
            # set Bugzilla ID as meta attribute
            meta_attr = extra_fields.get("meta_attr", {})
            meta_attr["bz_id"] = bz_id
            extra_fields["meta_attr"] = meta_attr
            return Flaw(**extra_fields)

    @staticmethod
    def fts_search(q):
        """full text search using postgres FTS via django.contrib.postgres"""
        from osidb.filters import search_helper

        return search_helper(Flaw.objects.get_queryset(), (), q)
        # Search default Flaw fields (title, comment_zero, cve_description, statement) with default weights
        # If search has no results, this will now return an empty queryset


@pghistory.track(
    pghistory.InsertEvent(),
    pghistory.UpdateEvent(),
    pghistory.DeleteEvent(),
    exclude="local_updated_dt,meta_attr,_alerts",
    model_name="FlawAudit",
)
class Flaw(
    AlertMixin,
    ACLMixin,
    TrackingMixin,
    JiraTaskSyncMixin,
    BugzillaSyncMixin,
    NullStrFieldsMixin,
    WorkflowModel,
):
    """Model flaw"""

    class FlawMajorIncident(models.TextChoices):
        """
        Stores a Major Incident (MI) state.

        Valid states are: NOVALUE, REQUESTED, REJECTED, APPROVED, CISA_APPROVED.

        Valid states represent the following BZ combinations in the format
        `<hightouch flag>|<hightouch-lite flag>`:

            ( | ): no flags set (NOVALUE)
            (?| ), ( |?), (?|?): MI, CISA MI, or both requested (REQUESTED)
            (-| ), ( |-), (-|-): MI, CISA MI, or both rejected (REJECTED)
            (+| ), (+|-): MI approved (APPROVED)
            ( |+), (-|+): CISA MI approved (CISA_APPROVED)

        If a state does not match any of BZ combinations, INVALID is set.
        """

        NOVALUE = ""
        REQUESTED = "REQUESTED"
        REJECTED = "REJECTED"
        APPROVED = "APPROVED"
        CISA_APPROVED = "CISA_APPROVED"
        MINOR = "MINOR"
        ZERO_DAY = "ZERO_DAY"
        INVALID = "INVALID"

    class FlawNistCvssValidation(models.TextChoices):
        """
        This flag determines the status of feedback loop between NIST and RH
        requesting NVD CVSSv3 rescore for the CVE of this flaw.
        The flag states have the following meaning:

        * ( ) "" (no value): No CVSSv3 rescore request was sent to NIST.
        * (?) "REQUESTED": CVSSv3 rescore request was sent to NIST and the
              feedback loop between NIST and RH is still opened.
        * (+) "APPROVED": CVSSv3 rescore request feedback loop between NIST and
              RH was closed and NIST fully or partially accepted the request
              lowering NVD score below 7.0.
        * (-) "REJECTED": CVSSv3 rescore request feedback loop between NIST and
              RH was closed and NIST rejected the request or accepted it only
              partially so the NVD CVSSv3 score is still above or equal 7.0.
        """

        NOVALUE = ""
        REQUESTED = "REQUESTED"
        APPROVED = "APPROVED"
        REJECTED = "REJECTED"

    class FlawRequiresCVEDescription(models.TextChoices):
        """
        Stores cve_description state from the requires_doc_text flag in BZ.

        The flag states have the following meaning:

        * ( ) "" (no value): cve_description was not filled in
        * (?) "REQUESTED": cve_description was filled in and a review was requested;
              this includes also the "+" state set by "bugzilla@redhat.com"
        * (+) "APPROVED" (set by PS member): cve_description was reviewed and approved;
              this is the only state where cve_description is propagated to the flaw's CVE page
        * (-) "REJECTED": cve_description is not required for this flaw

        Note that if a flaw is MI or CISA MI, requires_cve_description should be "APPROVED".
        """

        NOVALUE = ""
        REQUESTED = "REQUESTED"
        APPROVED = "APPROVED"
        REJECTED = "REJECTED"

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # CVE-ID, should be unique, from BZ alias
    # but may be also unset temporarily or permanently
    cve_id = models.CharField(
        max_length=500,
        null=True,
        unique=True,
        validators=[validate_cve_id],
        blank=True,
    )

    impact = models.CharField(choices=Impact.choices, max_length=20, blank=True)

    components = fields.ArrayField(
        models.CharField(max_length=100, blank=True), default=list, blank=True
    )
    # from BZ summary
    title = models.TextField()

    # from BZ description
    comment_zero = models.TextField()

    # from doc_text summary
    cve_description = models.TextField(blank=True)

    requires_cve_description = models.CharField(
        choices=FlawRequiresCVEDescription.choices, max_length=20, blank=True
    )

    # if redhat cve-id then this is required
    # eventually should compose up from affects
    statement = models.TextField(blank=True)

    # contains a single cwe-id or cwe relationships
    cwe_id = models.CharField(blank=True, max_length=255, validators=[validate_cwe_id])

    # date when embargo is to be lifted
    unembargo_dt = models.DateTimeField(null=True, blank=True)

    # reported source of flaw
    source = models.CharField(choices=FlawSource.choices, max_length=500, blank=True)

    # reported date
    reported_dt = models.DateTimeField(
        null=True, blank=True, validators=[no_future_date]
    )

    # mitigation to apply if the final fix is not available
    mitigation = models.TextField(blank=True)

    major_incident_state = models.CharField(
        choices=FlawMajorIncident.choices, max_length=20, blank=True
    )

    # The date when the flaw became a major incident, or null if it's not a major incident.
    # This field is either synced with BZ or handled by a signal.
    major_incident_start_dt = models.DateTimeField(null=True, blank=True)

    # non operational meta data
    meta_attr = HStoreField(default=dict)

    nist_cvss_validation = models.CharField(
        choices=FlawNistCvssValidation.choices, max_length=20, blank=True
    )

    local_updated_dt = models.DateTimeField(default=timezone.now)

    class Meta:
        """define meta"""

        verbose_name = "Flaw"
        # at least one of the columns to order by must be unique, indexed,
        # and never-changing in order to guarantee proper pagination.
        ordering = (
            "created_dt",
            "uuid",
        )
        indexes = TrackingMixin.Meta.indexes + [
            models.Index(fields=["-cve_id"]),
            GinIndex(fields=["acl_read"]),
            models.Index(fields=["-local_updated_dt"]),
        ]

    def __str__(self):
        """convert to string"""
        return str(self.uuid)

    def save(self, *args, **kwargs):
        # Automatically convert empty string values to null, since validation is skipped for
        # empty strings
        if self.cve_id == "":
            self.cve_id = None
        super().save(*args, **kwargs)

    def _validate_rh_nist_cvss_score_diff(self, **kwargs):
        """
        Checks that the difference between the RH and NIST CVSSv3 score is not >= 1.0.
        """
        from osidb.dmodels.flaw.cvss import FlawCVSS

        cvss_scores_v3 = self.cvss_scores.filter(version=FlawCVSS.CVSSVersion.VERSION3)
        nist_score = (
            cvss_scores_v3.filter(issuer=FlawCVSS.CVSSIssuer.NIST)
            .values_list("score", flat=True)
            .first()
        )
        rh_score = (
            cvss_scores_v3.filter(issuer=FlawCVSS.CVSSIssuer.REDHAT)
            .values_list("score", flat=True)
            .first()
        )

        if not nist_score or not rh_score:
            return

        if abs(nist_score - rh_score) >= Decimal("1.0"):
            self.alert(
                "rh_nist_cvss_score_diff",
                f"RH and NIST CVSSv3 score differs by 1.0 or more - "
                f"RH {rh_score} | NIST {nist_score}.",
                **kwargs,
            )

    def _validate_rh_nist_cvss_severity_diff(self, **kwargs):
        """
        Checks that the NIST and RH CVSSv3 score are not of a different severity.
        """
        from osidb.dmodels.flaw.cvss import FlawCVSS

        cvss_scores_v3 = self.cvss_scores.filter(version=FlawCVSS.CVSSVersion.VERSION3)
        nist_score = (
            cvss_scores_v3.filter(issuer=FlawCVSS.CVSSIssuer.NIST)
            .values_list("score", flat=True)
            .first()
        )
        rh_score = (
            cvss_scores_v3.filter(issuer=FlawCVSS.CVSSIssuer.REDHAT)
            .values_list("score", flat=True)
            .first()
        )

        if not nist_score or not rh_score:
            return

        rh_severity = nist_severity = None
        for key, value in CVSS3_SEVERITY_SCALE.items():
            lower, upper = value

            if lower <= rh_score <= upper:
                rh_severity = key

            if lower <= nist_score <= upper:
                nist_severity = key

        if rh_severity != nist_severity:
            self.alert(
                "rh_nist_cvss_severity_diff",
                "RH and NIST CVSSv3 score difference crosses severity boundary - "
                f"RH {rh_score}:{rh_severity} | "
                f"NIST {nist_score}:{nist_severity}.",
                **kwargs,
            )

    def _validate_rh_products_in_affects(self, **kwargs):
        """
        Returns True if a flaw has RH products in its affects list, False otherwise.
        """
        rh_pruducts = PsModule.objects.exclude(
            Q(ps_product__business_unit="Community") | Q(name__startswith="rhel-br-")
        ).values_list("name", flat=True)

        flaw_products = self.affects.values_list("ps_module", flat=True)

        # set() is used because querysets are of different types
        return bool(set(rh_pruducts) & set(flaw_products))

    def _validate_nist_rh_cvss_feedback_loop(self, **kwargs):
        """
        Checks whether RH should send a request to NIST on flaw CVSS rescore.

        The request should be sent if the flaw meets the following conditions:
        * it has NIST CVSS3 score of 7.0 or higher
        * it has RH CVSS3 score, which differs by 1.0 or more from NIST CVSS3 score
        * it affects at least one RH product
        * it has no associated NIST feedback loop in progress (see nist_cvss_validation)
        * it has no RH CVSS3 explanation comment
        """
        from osidb.dmodels.flaw.cvss import FlawCVSS

        nist_cvss = self.cvss_scores.filter(
            issuer=FlawCVSS.CVSSIssuer.NIST,
            version=FlawCVSS.CVSSVersion.VERSION3,
            score__gte=Decimal("7.0"),
        ).first()

        rh_cvss = self.cvss_scores.filter(
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            version=FlawCVSS.CVSSVersion.VERSION3,
            comment__exact="",
        ).first()

        if (
            nist_cvss
            and rh_cvss
            and self._validate_rh_products_in_affects()
            and not self.nist_cvss_validation
            and abs(nist_cvss.score - rh_cvss.score) >= Decimal("1.0")
        ):
            self.alert(
                "request_nist_cvss_validation",
                f"NIST CVSSv3 score ({nist_cvss.score}) is significantly different "
                f"from the RH-assigned CVSSv3 score ({rh_cvss.score}). "
                f"Consider requesting CVSSv3 rescoring from NIST or add "
                f"an explanation comment for RH CVSSv3 score.",
                **kwargs,
            )

    def _validate_cvss_scores_and_nist_cvss_validation(self, **kwargs):
        """
        Checks that if nist_cvss_validation is set, then both NIST CVSSv3 and RH CVSSv3
        scores need to be present.
        """
        from osidb.dmodels.flaw.cvss import FlawCVSS

        nist_cvss = self.cvss_scores.filter(
            issuer=FlawCVSS.CVSSIssuer.NIST,
            version=FlawCVSS.CVSSVersion.VERSION3,
        ).first()

        rh_cvss = self.cvss_scores.filter(
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            version=FlawCVSS.CVSSVersion.VERSION3,
        ).first()

        if self.nist_cvss_validation and not (nist_cvss and rh_cvss):
            raise ValidationError(
                "nist_cvss_validation can only be set if a flaw has both "
                "NIST CVSSv3 and RH CVSSv3 scores assigned.",
            )

    def _validate_impact_and_cve_description(self, **kwargs):
        """
        Checks that if impact has MODERATE, IMPORTANT or CRITICAL value set,
        then cve_description must not be missing.
        """
        if (
            self.impact in [Impact.MODERATE, Impact.IMPORTANT, Impact.CRITICAL]
            and not self.cve_description
        ):
            self.alert(
                "impact_without_cve_description",
                f"cve_description cannot be missing if impact is {self.impact}.",
                **kwargs,
            )

    def _validate_cve_description_and_requires_cve_description(self, **kwargs):
        """
        Checks that if cve_description is missing, then requires_cve_description must not have
        REQUESTED or APPROVED value set.
        """
        if not self.cve_description and self.requires_cve_description in [
            self.FlawRequiresCVEDescription.REQUESTED,
            self.FlawRequiresCVEDescription.APPROVED,
        ]:
            raise ValidationError(
                f"requires_cve_description cannot be {self.requires_cve_description} if cve_description is "
                f"missing."
            )

    def _validate_requires_cve_description(self, **kwargs):
        """
        Checks that if requires_cve_description was already set to
        something other than NOVALUE, it cannot be set to NOVALUE.
        """
        if self._state.adding:
            # we're creating a new flaw so we don't need to check whether we're
            # changing from one state to another
            return

        old_flaw = Flaw.objects.get(pk=self.pk)
        if (
            old_flaw.requires_cve_description != self.FlawRequiresCVEDescription.NOVALUE
            and self.requires_cve_description == self.FlawRequiresCVEDescription.NOVALUE
        ):
            raise ValidationError(
                "requires_cve_description cannot be unset if it was previously set to something other than NOVALUE"
            )

    def _validate_nonempty_source(self, **kwargs):
        """
        checks that the source is not empty

        we cannot enforce this by model definition
        as the old flaws may have no source
        """
        if not self.source:
            raise ValidationError("Source value is required.")

    def _validate_embargoed_source(self, **kwargs):
        """
        Checks that the source is private if the Flaw is embargoed.
        """
        if not self.source:
            return

        if (
            self.is_embargoed
            and (source := FlawSource(self.source))
            and source.is_public()
        ):
            if source.is_private():
                self.alert(
                    "embargoed_source_public",
                    f"Flaw source of type {source} can be public or private, "
                    "ensure that it is private since the Flaw is embargoed.",
                    **kwargs,
                )
            else:
                raise ValidationError(
                    f"Flaw is embargoed but contains public source: {self.source}"
                )

    def _validate_reported_date(self, **kwargs):
        """
        Checks that the flaw has non-empty reported_dt
        """
        if self.reported_dt is None:
            raise ValidationError("Flaw has an empty reported_dt")

    def _validate_public_unembargo_date(self, **kwargs):
        """
        Check that an unembargo date (public date) exists and is in the past if the Flaw is public
        """
        if not self.is_embargoed:
            if self.unembargo_dt is None:
                raise ValidationError("Public flaw has an empty unembargo_dt")
            if self.unembargo_dt > timezone.now():
                raise ValidationError("Public flaw has a future unembargo_dt")

    def _validate_future_unembargo_date(self, **kwargs):
        """
        Check that an enbargoed flaw has an unembargo date in the future
        """
        if (
            self.is_embargoed
            and self.unembargo_dt is not None
            and self.unembargo_dt < timezone.now()
        ):
            raise ValidationError(
                "Flaw still embargoed but unembargo date is in the past."
            )

    def _validate_cvss3(self, **kwargs):
        """
        Check that a CVSSv3 string is present.
        """
        from osidb.dmodels.flaw.cvss import FlawCVSS

        rh_cvss3 = self.cvss_scores.filter(
            version=FlawCVSS.CVSSVersion.VERSION3, issuer=FlawCVSS.CVSSIssuer.REDHAT
        ).first()

        if not rh_cvss3:
            self.alert(
                "cvss3_missing",
                "CVSSv3 score is missing.",
                **kwargs,
            )

    def _validate_major_incident_state(self, **kwargs):
        """
        Checks that a flaw has a valid Major Incident state.
        """
        if self.major_incident_state == self.FlawMajorIncident.INVALID:
            raise ValidationError("A flaw does not have a valid Major Incident state.")

        # XXX: In SFM2 we check that the REQUIRES_DOC_TEXT flag is set by
        # someone who has review access rights, it is uncertain whether
        # we'd need this in OSIDB as ideally we would block non-authorized
        # users from reviewing in the first place, in which case we don't
        # need to perform this validation

    def _validate_major_incident_fields(self, **kwargs):
        """
        Validate that a Flaw that is Major Incident or 0-day complies with the following:
        * has a mitigation
        * has a statement
        * has a cve_description
        * requires_cve_description is APPROVED
        * has exactly one article
        """
        from osidb.dmodels.flaw.reference import FlawReference

        if self.major_incident_state not in [
            Flaw.FlawMajorIncident.APPROVED,
            Flaw.FlawMajorIncident.ZERO_DAY,
        ]:
            return

        if not self.mitigation:
            self.alert(
                "mi_mitigation_missing",
                "Flaw marked as Major Incident does not have a mitigation.",
                **kwargs,
            )

        if not self.statement:
            self.alert(
                "mi_statement_missing",
                "Flaw marked as Major Incident does not have a statement.",
                **kwargs,
            )

        if not self.cve_description:
            self.alert(
                "mi_cve_description_missing",
                "Flaw marked as Major Incident does not have a cve_description.",
                **kwargs,
            )

        if self.requires_cve_description != self.FlawRequiresCVEDescription.APPROVED:
            self.alert(
                "mi_cve_description_not_reviewed",
                "Flaw marked as Major Incident does not have a cve_description reviewed.",
                **kwargs,
            )

        article = self.references.filter(type=FlawReference.FlawReferenceType.ARTICLE)
        if article.count() != 1:
            self.alert(
                "mi_article_missing",
                "Flaw marked as Major Incident must have exactly one article.",
                **kwargs,
            )

    def _validate_cisa_major_incident_fields(self, **kwargs):
        """
        Validate that a Flaw that is CISA Major Incident complies with the following:
        * has a statement
        * has a cve_description
        * requires_cve_description is APPROVED
        """
        if self.major_incident_state != Flaw.FlawMajorIncident.CISA_APPROVED:
            return

        if not self.statement:
            self.alert(
                "cisa_mi_statement_missing",
                "Flaw marked as CISA Major Incident does not have a statement.",
                **kwargs,
            )

        if not self.cve_description:
            self.alert(
                "cisa_mi_cve_description_missing",
                "Flaw marked as CISA Major Incident does not have a cve_description.",
                **kwargs,
            )

        if self.requires_cve_description != self.FlawRequiresCVEDescription.APPROVED:
            self.alert(
                "cisa_mi_cve_description_not_reviewed",
                "Flaw marked as CISA Major Incident does not have a cve_description reviewed.",
                **kwargs,
            )

    def _validate_embargoing_public_flaw(self, **kwargs):
        """
        Check whether a currently public flaw is being embargoed.
        """
        if self._state.adding:
            # we're creating a new flaw so we don't need to check whether we're
            # changing from one state to another
            return
        old_flaw = Flaw.objects.get(pk=self.pk)
        if not old_flaw.embargoed and self.is_embargoed:
            raise ValidationError("Embargoing a public flaw is futile")

    def _validate_cwe_format(self, **kwargs):
        """
        Check if CWE string is well formated
        """
        cwe_data = self.cwe_id
        # First, remove possible [auto] suffix from the CWE entry
        # [auto] suffix means value was assigned by a script during mass update
        if len(cwe_data) > 6 and cwe_data.endswith("[auto]"):
            cwe_data = cwe_data[:-6]

        # Then split data on arrows ->, later we will parse the elements separately
        arrow_count = len(re.findall("->", cwe_data))
        parsed_elements = list(filter(None, cwe_data.split("->")))

        # Ensure number of elements is one bigger then count of arrows, to catch
        # stuff like: CWE-123->
        if len(parsed_elements) > 0 and len(parsed_elements) != (arrow_count + 1):
            raise ValidationError(
                "CWE IDs is not well formated. Incorrect number of -> in CWE field."
            )

        # Ensure each element is well formed, i.e. one of:
        #   * CWE-123
        #   * (CWE-123)
        #   * (CWE-123|CWE-456)
        for element in parsed_elements:
            if not re.match(r"^(CWE-[0-9]+|\(CWE-[0-9]+(\|CWE-[0-9]+)*\))$", element):
                raise ValidationError("CWE IDs is not well formated.")

    def _validate_flaw_without_affect(self, **kwargs):
        """
        Check if flaw have at least one affect
        """
        # Skip validation at creation allowing to draft a Flaw
        if self._state.adding:
            return

        from osidb.dmodels.affect import Affect  # TODO

        if not Affect.objects.filter(flaw=self).exists():
            err = ValidationError("Flaw does not contain any affects.")
            # When a flaw without state or in a "new" workflow state is modified, allow saving
            # with no affects but issue an alert
            if self.workflow_state in {
                WorkflowModel.WorkflowState.NOVALUE,
                WorkflowModel.WorkflowState.NEW,
            }:
                self.alert(
                    "_validate_flaw_without_affect",
                    err.message,
                    alert_type=Alert.AlertType.ERROR,
                    **kwargs,
                )
            else:
                raise err

    def _validate_nonempty_components(self, **kwargs):
        """
        check that the component list is not empty

        we cannot enforce this by model definition
        as the old flaws may have no components
        """
        if not self.components:
            raise ValidationError("Components value is required.")

    def _validate_unsupported_impact_change(self, **kwargs):
        """
        Check that an update of a flaw with open trackers does not change between
        Critical/Important/Major Incident and Moderate/Low and vice-versa.
        """
        from osidb.dmodels.tracker import Tracker

        if self._state.adding:
            return

        old_flaw = Flaw.objects.get(pk=self.pk)
        was_high_impact = old_flaw.impact in [
            Impact.CRITICAL,
            Impact.IMPORTANT,
        ] or old_flaw.major_incident_state in [
            Flaw.FlawMajorIncident.APPROVED,
            Flaw.FlawMajorIncident.CISA_APPROVED,
            # Flaw.FlawMajorIncident.MINOR is not
            # included as it is only informative
            Flaw.FlawMajorIncident.ZERO_DAY,
        ]
        is_high_impact = self.impact in [
            Impact.CRITICAL,
            Impact.IMPORTANT,
        ] or self.major_incident_state in [
            Flaw.FlawMajorIncident.APPROVED,
            Flaw.FlawMajorIncident.CISA_APPROVED,
            # Flaw.FlawMajorIncident.MINOR is not
            # included as it is only informative
            Flaw.FlawMajorIncident.ZERO_DAY,
        ]
        if (
            was_high_impact != is_high_impact
            and Tracker.objects.filter(affects__flaw=self)
            .exclude(status="Closed")
            .exists()
        ):
            self.alert(
                "unsupported_impact_change",
                "Performed impact/Major Incident update is not supported because the flaw "
                "has unclosed trackers. Make sure to manually update all related trackers in "
                "accordance to the flaw bug changes.",
                **kwargs,
            )

    def _validate_no_placeholder(self, **kwargs):
        """
        restrict any write operations on placeholder flaws

        they have a special handling mainly in sense
        of visibility and we deprecate this concept
        """
        if self.is_placeholder:
            raise ValidationError(
                "OSIDB does not support write operations on placeholder flaws"
            )

    def _validate_special_consideration_flaw(self, **kwargs):
        """
        Checks that a flaw affecting special consideration package(s) has both
        cve_description and statement
        """
        if self.cve_description and self.statement:
            return

        affected_ps_components = self.affects.values_list("ps_component")
        affected_special_consideration_packages = (
            SpecialConsiderationPackage.objects.filter(name__in=affected_ps_components)
        ).values_list("name", flat=True)
        if affected_special_consideration_packages.exists():
            if not self.cve_description:
                self.alert(
                    "special_consideration_flaw_missing_cve_description",
                    "Flaw affecting special consideration package(s) "
                    f"{', '.join(affected_special_consideration_packages)} is missing cve_description.",
                    **kwargs,
                )
            if not self.statement:
                self.alert(
                    "special_consideration_flaw_missing_statement",
                    "Flaw affecting special consideration package(s) "
                    f"{', '.join(affected_special_consideration_packages)} is missing statement.",
                    **kwargs,
                )

    def _validate_private_source_no_ack(self, **kwargs):
        """
        Checks that flaws with private sources have ACK.
        """
        if (source := FlawSource(self.source)) and source.is_private():
            if self.acknowledgments.count() > 0:
                return

            if source.is_public():
                alert_text = (
                    f"Flaw source of type {source} can be public or private, "
                    "ensure that it is public since the Flaw has no acknowledgments."
                )
            else:
                alert_text = (
                    f"Flaw has no acknowledgments but source of type {source} is private, "
                    "include them in acknowledgments."
                )
            self.alert(
                "private_source_no_ack",
                alert_text,
                **kwargs,
            )

    def _validate_allowed_source(self, **kwargs):
        """
        Checks that the flaw source is allowed (not historical).
        """
        if (
            self.source
            and not FlawSource(self.source).is_allowed()
            and not FlawSource(self.source).is_from_snippet()
        ):
            raise ValidationError("The flaw has a disallowed (historical) source.")

    def _validate_article_links_count_via_flaw(self, **kwargs):
        """
        Checks that a flaw has maximally one article link.
        """
        from osidb.dmodels.flaw.reference import FlawReference

        if self.references:
            article_links = self.references.filter(
                type=FlawReference.FlawReferenceType.ARTICLE
            )

            if article_links.count() > 1:
                raise ValidationError(
                    f"A flaw has {article_links.count()} article links, "
                    f"but only 1 is allowed."
                )

    @property
    def is_placeholder(self):
        """
        placeholder flaws contain a special Bugzilla keyword
        """
        return FLAW_PLACEHOLDER_KEYWORD in json.loads(
            self.meta_attr.get("keywords", "[]")
        )

    @property
    def bz_id(self):
        """
        shortcut to get underlying Bugzilla bug ID
        """
        return self.meta_attr.get("bz_id", None)

    @bz_id.setter
    def bz_id(self, value):
        """
        shortcut to set underlying Bugzilla bug ID
        """
        self.meta_attr["bz_id"] = value

    @property
    def api_url(self):
        """return osidb api url"""
        return f"/api/{OSIDB_API_VERSION}/{self.uuid}"

    objects = FlawManager()

    def get_affect(self, ps_module, ps_component):
        """return related affect by PS module and PS component"""
        return self.affects.filter(
            # case sensitivity does not matter
            ps_module__iexact=ps_module,
            ps_component__iexact=ps_component,
        ).first()

    # TODO here or in separate check definition module ?
    @property
    def affects_notaffected(self):
        """check that all affects are in NOTAFFECTED state"""
        from osidb.dmodels.affect import Affect  # TODO

        return not self.affects.exclude(
            affectedness=Affect.AffectAffectedness.NOTAFFECTED
        ).exists()

    @property
    def affects_resolved(self):
        """check that all affects have resolution"""
        from osidb.dmodels.affect import Affect  # TODO

        return not self.affects.filter(
            resolution=Affect.AffectResolution.NOVALUE
        ).exists()

    @property
    def trackers_filed(self):
        """
        check that all affects in
        NEW:NOVALUE or AFFECTED:DELEGATED
        have associated trackers filed
        """
        from osidb.dmodels.affect import Affect  # TODO

        return all(
            affect.trackers.exists()
            for affect in self.affects.filter(
                affectedness=Affect.AffectAffectedness.NEW,
                resolution=Affect.AffectResolution.NOVALUE,
            )
        ) and all(
            affect.trackers.exists()
            for affect in self.affects.filter(
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
            )
        )

    @property
    def trackers_resolved(self):
        """check that all trackers have resolution"""
        # TODO we have no tracker resolution for now
        return False

    def bzsync(self, *args, force_synchronous_sync=False, **kwargs):
        """
        Bugzilla sync of the Flaw instance
        """
        if not SYNC_FLAWS_TO_BZ:
            return

        # switch of sync/async processing
        if SYNC_FLAWS_TO_BZ_ASYNCHRONOUSLY and not force_synchronous_sync:
            # Process the bzsync asynchronously
            BZSyncManager.check_for_reschedules()
            BZSyncManager.schedule(str(self.uuid))
        else:
            self._perform_bzsync(bz_api_key=kwargs.get("bz_api_key"), no_alerts=True)

    def _perform_bzsync(self, *args, bz_api_key=None, no_alerts=False, **kwargs):
        """
        Helper function that contains the actual logic of the Bugzilla sync,
        without additional checks - only the one-way sync to Bugzilla.
        """
        # imports here to prevent cycles
        from apps.bbsync.save import FlawBugzillaSaver

        creating = self.bz_id is None

        try:
            # sync to Bugzilla
            bs = FlawBugzillaSaver(self, bz_api_key)  # prepare data for save to BZ
            flaw_instance = bs.save()  # actually send to BZ (but not save to DB)

            if creating:
                # Save bz_id to DB
                kwargs["auto_timestamps"] = False  # no timestamps changes on save to BZ
                kwargs[
                    "raise_validation_error"
                ] = False  # the validations were already run
                # save in case a new Bugzilla ID was obtained
                # Instead of self.save(*args, **kwargs), just update the single field to avoid
                # race conditions.
                flaw_instance.save(
                    *args, update_fields=["meta_attr"], no_alerts=no_alerts, **kwargs
                )
        except Exception as e:
            # Sync failed but if it was done async the original flaw may be saved, resulting in
            # incosnsitent data between OSIDB and BZ.
            logger.error(f"Error when syncing flaw {self.uuid} to Bugzilla: {e}.")
            self.alert(
                "bzsync_failed",
                "The Bugzilla sync for this flaw failed in the last save, so there may be data discrepancies. "
                "The Vulnerability Tooling team has been notified about this and is looking into it.",
                Alert.AlertType.ERROR,
            )
            raise e

        # If the bzsync was performed correctly, remove any possible alert on previously failed bzsync
        self.alerts.filter(name="bzsync_failed").delete()

    def tasksync(
        self,
        jira_token,
        force_creation=False,
        force_update=False,
        *args,
        **kwargs,
    ):
        """
        Task sync of the Flaw instance in Jira.

        If the flaw is OSIDB-authored and already exists in the database
        the corresponding JIRA task will be updated if any of the
        SYNC_REQUIRED_FIELDS has been updated.

        If the flaw is OSIDB-authored and comes from collectors (exists in the database),
        then a corresponding JIRA task will be created.

        If the flaw is OSIDB-authored and does not exist in the database
        then a corresponding JIRA task will be created.

        If the flaw is not OSIDB-authored then it's a no-op.
        """

        def _create_new_flaw():
            issue = jtq.create_or_update_task(self)
            self.task_key = issue.data["key"]
            self.task_updated_dt = datetime.strptime(
                issue.data["fields"]["updated"], "%Y-%m-%dT%H:%M:%S.%f%z"
            )
            self.workflow_state = WorkflowModel.WorkflowState.NEW
            self.save(no_alerts=True, *args, **kwargs)

        if not JIRA_TASKMAN_AUTO_SYNC_FLAW or not jira_token:
            return

        # imports here to prevent cycles
        from apps.taskman.service import JiraTaskmanQuerier

        jtq = JiraTaskmanQuerier(token=jira_token)
        kwargs["auto_timestamps"] = False  # the timestamps will be get from Bugzilla
        kwargs["raise_validation_error"] = False  # the validations were already run

        # REST API can force new tasks since it has no access to flaw creation runtime -- create
        if force_creation:
            _create_new_flaw()
            return

        try:
            old_flaw = Flaw.objects.get(uuid=self.uuid)

            # we're handling a new OSIDB-authored flaw from collectors -- create
            if not old_flaw.meta_attr.get("bz_id") and old_flaw.task_key == "":
                _create_new_flaw()
                return

            # the flaw exists but the task doesn't, not an OSIDB-authored flaw -- no-op
            if not old_flaw.task_key:
                return

            # we're handling an existing OSIDB-authored flaw -- update
            if force_update or any(
                getattr(old_flaw, field) != getattr(self, field)
                for field in SYNC_REQUIRED_FIELDS
            ):
                issue = jtq.create_or_update_task(self)
                status = issue.data["fields"]["status"]["name"]
                resolution = issue.data["fields"]["resolution"]
                resolution = resolution["name"] if resolution else None

                framework = WorkflowFramework()
                workflow_name, workflow_state = framework.jira_to_state(
                    status, resolution
                )
                self.workflow_state = workflow_state
                self.workflow_name = workflow_name
                self.task_updated_dt = datetime.strptime(
                    issue.data["fields"]["updated"], "%Y-%m-%dT%H:%M:%S.%f%z"
                )
                self.adjust_acls(save=False)
                self.save(no_alerts=True, *args, **kwargs)
        except Flaw.DoesNotExist:
            # we're handling a new OSIDB-authored flaw -- create
            _create_new_flaw()

    download_manager = models.ForeignKey(
        FlawDownloadManager, null=True, blank=True, on_delete=models.CASCADE
    )
    task_download_manager = models.ForeignKey(
        JiraTaskDownloadManager, null=True, blank=True, on_delete=models.CASCADE
    )
    bzsync_manager = models.ForeignKey(
        BZSyncManager, null=True, blank=True, on_delete=models.CASCADE
    )
