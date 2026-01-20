from __future__ import annotations

import json
import logging
import re
import uuid
from decimal import Decimal

import pghistory
from django.contrib.postgres import fields
from django.contrib.postgres.indexes import GinIndex
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import models
from django.db.models import JSONField, Q
from django.utils import timezone
from psqlextra.fields import HStoreField

from apps.bbsync.constants import SYNC_FLAWS_TO_BZ, SYNC_FLAWS_TO_BZ_ASYNCHRONOUSLY
from apps.bbsync.mixins import BugzillaSyncMixin
from apps.taskman.constants import (
    JIRA_TASKMAN_ASYNCHRONOUS_SYNC,
    SYNC_REQUIRED_FIELDS,
    TRANSITION_REQUIRED_FIELDS,
)
from apps.taskman.mixins import JiraTaskSyncMixin
from apps.workflows.workflow import WorkflowModel, WorkflowModelManager
from collectors.bzimport.constants import FLAW_PLACEHOLDER_KEYWORD
from osidb.constants import CVSS3_SEVERITY_SCALE, OSIDB_API_VERSION
from osidb.mixins import (
    ACLMixin,
    ACLMixinManager,
    Alert,
    AlertMixin,
    NullStrFieldsMixin,
    TrackingMixin,
    TrackingMixinManager,
)
from osidb.models import FlawSource, Impact, PsModule, SpecialConsiderationPackage
from osidb.models.fields import CVEIDField
from osidb.query_sets import CustomQuerySetUpdatedDt
from osidb.sync_manager import (
    BZSyncManager,
    JiraTaskDownloadManager,
    JiraTaskSyncManager,
    JiraTaskTransitionManager,
)
from osidb.validators import no_future_date, validate_cwe_id

logger = logging.getLogger(__name__)


class FlawManager(ACLMixinManager, TrackingMixinManager, WorkflowModelManager):
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

    @staticmethod
    def get_by_identifier(id, queryset=None):
        """
        Get a flaw by its identifier: CVE ID or UUID.
        Match CVE ID case-insensitively and default to UUID if CVE does not match.

        Optionally accepts a custom Flaw queryset to fetch from.
        """
        from osidb.validators import CVE_RE_STR

        if queryset is None:
            queryset = Flaw.objects
        elif queryset.model != Flaw:
            raise ValidationError("queryset must be a Flaw queryset")

        id_upper = id.upper()
        cve_match = CVE_RE_STR.match(id_upper)

        if cve_match:
            return queryset.get(cve_id=id_upper)

        return queryset.get(pk=id)


@pghistory.track(
    pghistory.InsertEvent(),
    pghistory.UpdateEvent(),
    pghistory.DeleteEvent(),
    exclude="local_updated_dt,meta_attr",
    model_name="FlawAudit",
)
class Flaw(
    ACLMixin,
    AlertMixin,
    BugzillaSyncMixin,
    # the task management must go after the Bugzilla sync
    # since we need to determine first whether it triggers
    JiraTaskSyncMixin,
    TrackingMixin,
    NullStrFieldsMixin,
    WorkflowModel,
):
    """Model flaw"""

    class FlawMajorIncident(models.TextChoices):
        """
        Stores a Major Incident (MI) state.

        Valid states are:
        - No value:NOVALUE
        - Major Incident:
            MAJOR_INCIDENT_REQUESTED, MAJOR_INCIDENT_REJECTED, MAJOR_INCIDENT_APPROVED
        - Exploits (KEV):
            EXPLOITS_KEV_REQUESTED, EXPLOITS_KEV_REJECTED, EXPLOITS_KEV_APPROVED
        - Minor Incident:
            MINOR_INCIDENT_REQUESTED, MINOR_INCIDENT_REJECTED, MINOR_INCIDENT_APPROVED

        Valid states represent the following BZ combinations in the format
        `<hightouch flag>|<hightouch-lite flag>`:

            ( | ): no flags set (NOVALUE)
            (?| ), (?|?): MI requested (MAJOR_INCIDENT_REQUESTED)
            ( |?): Exploits (KEV) requested (EXPLOITS_KEV_REQUESTED)
            (-| ), (-|-): MI rejected (MAJOR_INCIDENT_REJECTED)
            ( |-): Exploits (KEV) rejected (EXPLOITS_KEV_REJECTED)
            (+| ), (+|-): MI approved (MAJOR_INCIDENT_APPROVED)
            ( |+), (-|+): Exploits (KEV) approved (EXPLOITS_KEV_APPROVED)

        If a state does not match any of BZ combinations, INVALID is set.
        """

        NOVALUE = ""
        MAJOR_INCIDENT_REQUESTED = "MAJOR_INCIDENT_REQUESTED"
        MAJOR_INCIDENT_REJECTED = "MAJOR_INCIDENT_REJECTED"
        MAJOR_INCIDENT_APPROVED = "MAJOR_INCIDENT_APPROVED"
        EXPLOITS_KEV_REQUESTED = "EXPLOITS_KEV_REQUESTED"
        EXPLOITS_KEV_REJECTED = "EXPLOITS_KEV_REJECTED"
        EXPLOITS_KEV_APPROVED = "EXPLOITS_KEV_APPROVED"
        MINOR_INCIDENT_REQUESTED = "MINOR_INCIDENT_REQUESTED"
        MINOR_INCIDENT_REJECTED = "MINOR_INCIDENT_REJECTED"
        MINOR_INCIDENT_APPROVED = "MINOR_INCIDENT_APPROVED"

        @classmethod
        def request_states(cls) -> list[Flaw.FlawMajorIncident]:
            return [
                cls.MAJOR_INCIDENT_REQUESTED,
                cls.EXPLOITS_KEV_REQUESTED,
                cls.MINOR_INCIDENT_REQUESTED,
            ]

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

        Note that if a flaw is MI or Exploits (KEV), requires_cve_description should be "APPROVED".
        """

        NOVALUE = ""
        REQUESTED = "REQUESTED"
        APPROVED = "APPROVED"
        REJECTED = "REJECTED"

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # CVE-ID, should be unique, from BZ alias
    # but may be also unset temporarily or permanently
    cve_id = CVEIDField()

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
        choices=FlawMajorIncident.choices, max_length=24, blank=True
    )

    # The date when the flaw became a major incident, or null if it's not a major incident.
    # This field is either synced with BZ or handled by a signal.
    major_incident_start_dt = models.DateTimeField(null=True, blank=True)

    # non operational meta data
    meta_attr = HStoreField(default=dict)
    # aegis metadata
    aegis_meta = JSONField(default=dict, blank=True)

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

        # provide the save diff as an argument
        # so we can freely save and still have it
        if not self._state.adding:
            old_flaw = Flaw.objects.get(uuid=self.uuid)

            diff = {}
            for field in self._meta.fields:
                if getattr(old_flaw, field.name) != getattr(self, field.name):
                    diff[field.name] = {
                        "old": getattr(old_flaw, field.name),
                        "new": getattr(self, field.name),
                    }
            kwargs["diff"] = diff

        super().save(*args, **kwargs)

    def _validate_major_incident_state_reset(self, **kwargs) -> None:
        """
        Checks that major_incident_state can't be reset.
        """
        if self._state.adding:
            return

        old_flaw = Flaw.objects.get(pk=self.pk)

        if (
            old_flaw.major_incident_state != self.major_incident_state
            and self.major_incident_state == Flaw.FlawMajorIncident.NOVALUE
        ):
            raise ValidationError("Cannot revert major_incident_state back to NOVALUE")

    def _validate_rh_nist_cvss_score_diff(self, **kwargs):
        """
        Checks that the difference between the RH and NIST CVSSv3 score is not >= 1.0.
        """
        from .cvss import FlawCVSS

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
        from .cvss import FlawCVSS

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
        from .cvss import FlawCVSS

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
        scores need to be present unless NIST fully accepted our score and deleted theirs.
        """
        from .cvss import FlawCVSS

        nist_cvss = self.cvss_scores.filter(
            issuer=FlawCVSS.CVSSIssuer.NIST,
            version=FlawCVSS.CVSSVersion.VERSION3,
        ).first()

        rh_cvss = self.cvss_scores.filter(
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            version=FlawCVSS.CVSSVersion.VERSION3,
        ).first()

        if self.nist_cvss_validation and not (nist_cvss and rh_cvss):
            # it may happen that NIST accepts our score and deletes theirs and
            # then having a record in the sense of an approved flag makes sense
            if self.nist_cvss_validation == self.FlawNistCvssValidation.APPROVED:
                return
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

    def _validate_rh_cvss3_and_impact(self, **kwargs):
        """
        Validate that flaw's RH CVSSv3 score and impact comply with the following:
        * RH CVSSv3 score is not zero and flaw impact is set
        * RH CVSSv3 score is zero and flaw impact is not set
        """
        from .cvss import FlawCVSS

        rh_cvss3 = self.cvss_scores.filter(
            version=FlawCVSS.CVSSVersion.VERSION3, issuer=FlawCVSS.CVSSIssuer.REDHAT
        ).first()

        if rh_cvss3:
            if rh_cvss3.cvss_object.base_score == Decimal("0.0") and self.impact:
                self.alert(
                    "set_impact_with_zero_CVSSv3_score",
                    "Flaw impact must not be set if RH CVSSv3 score is zero.",
                    **kwargs,
                )
            if rh_cvss3.cvss_object.base_score != Decimal("0.0") and not self.impact:
                self.alert(
                    "unset_impact_with_nonzero_CVSSv3_score",
                    "Flaw impact must be set if RH CVSSv3 score is not zero.",
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
        Check that an unembargo date (public date) exists and is in the past if the Flaw is not embargoed
        """
        if not self.is_embargoed:
            if self.unembargo_dt is None:
                raise ValidationError("Non-embargoed flaw has an empty unembargo_dt")
            if self.unembargo_dt > timezone.now():
                raise ValidationError("Non-embargoed flaw has a future unembargo_dt")

    def _validate_future_unembargo_date(self, **kwargs):
        """
        Check that an embargoed flaw has an unembargo date in the future.
        Only validates when the unembargo date is newly set or has changed.
        """

        try:
            old_flaw = Flaw.objects.get(pk=self.pk)
            if old_flaw.unembargo_dt == self.unembargo_dt:
                return
        except Flaw.DoesNotExist:
            pass

        if (
            self.is_embargoed
            and self.unembargo_dt is not None
            and self.unembargo_dt.date() < timezone.now().date()
        ):
            raise ValidationError(
                "Flaw still embargoed but unembargo date is in the past."
            )

    def _validate_cvss3(self, **kwargs):
        """
        Check that a CVSSv3 string is present.
        """
        from .cvss import FlawCVSS

        rh_cvss3 = self.cvss_scores.filter(
            version=FlawCVSS.CVSSVersion.VERSION3, issuer=FlawCVSS.CVSSIssuer.REDHAT
        ).first()

        if not rh_cvss3:
            self.alert(
                "cvss3_missing",
                "CVSSv3 score is missing.",
                **kwargs,
            )

    def _validate_major_incident_fields(self, **kwargs):
        """
        Validate that a Flaw that is Major Incident complies with the following:
        * has a mitigation
        * has a statement
        * has a cve_description
        * has exactly one article
        """
        from .reference import FlawReference

        if self.major_incident_state != Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED:
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

        article = self.references.filter(type=FlawReference.FlawReferenceType.ARTICLE)
        if article.count() != 1:
            self.alert(
                "mi_article_missing",
                "Flaw marked as Major Incident must have exactly one article.",
                **kwargs,
            )

    def _validate_exploits_kev_fields(self, **kwargs):
        """
        Validate that a Flaw that is a Exploits (KEV) complies with the following:
        * has a statement
        * has a cve_description
        """
        if self.major_incident_state != Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED:
            return

        if not self.statement:
            self.alert(
                "exploits_kev_statement_missing",
                "Flaw marked as Exploits (KEV) does not have a statement.",
                **kwargs,
            )

        if not self.cve_description:
            self.alert(
                "exploits_kev_cve_description_missing",
                "Flaw marked as Exploits (KEV) does not have a cve_description.",
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

        # Split data on arrows ->, later we will parse the elements separately
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
        from osidb.models import Affect

        # Skip validation at creation allowing to draft a Flaw
        if self._state.adding:
            return

        if not Affect.objects.filter(flaw=self).exists():
            # When a flaw without afects is saved, issue an alert
            self.alert(
                "_validate_flaw_without_affect",
                "Flaw does not contain any affects.",
                alert_type=Alert.AlertType.ERROR,
                **kwargs,
            )

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
        from osidb.models import Tracker

        if self._state.adding:
            return

        old_flaw = Flaw.objects.get(pk=self.pk)
        was_high_impact = old_flaw.impact in [
            Impact.CRITICAL,
            Impact.IMPORTANT,
        ] or old_flaw.major_incident_state in [
            Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
            Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            # Flaw.FlawMajorIncident.MINOR_INCIDENT_APPROVED is not
            # included as it is only informative
        ]
        is_high_impact = self.impact in [
            Impact.CRITICAL,
            Impact.IMPORTANT,
        ] or self.major_incident_state in [
            Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
            Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            # Flaw.FlawMajorIncident.MINOR_INCIDENT_APPROVED is not
            # included as it is only informative
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
        from .reference import FlawReference

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

    objects = FlawManager.from_queryset(CustomQuerySetUpdatedDt)()

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
        from osidb.models import Affect

        return not self.affects.exclude(
            affectedness=Affect.AffectAffectedness.NOTAFFECTED
        ).exists()

    @property
    def affects_resolved(self):
        """check that all affects have resolution"""
        from osidb.models import Affect

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
        from osidb.models import Affect

        return all(
            affect.tracker is not None
            for affect in self.affects.filter(
                affectedness=Affect.AffectAffectedness.NEW,
                resolution=Affect.AffectResolution.NOVALUE,
            )
        ) and all(
            affect.tracker is not None
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

        try:
            # sync to Bugzilla
            bs = FlawBugzillaSaver(self, bz_api_key)  # prepare data for save to BZ
            bs.save()  # actually send to BZ and update meta attributes in the DB
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
        # NOTE: .using() is necessary here as Django will by default reuse the
        # db that was used for fetch for DELETE and UPDATE operations as of 4.2
        # see https://code.djangoproject.com/ticket/32965
        self.alerts.filter(name="bzsync_failed").using("default").delete()

    def tasksync(
        self,
        jira_token,
        diff=None,
        force_creation=False,
        *args,
        **kwargs,
    ):
        """
        decides what to do about the Jira task of this flaw

        based on the task existence it is either created or updated and/or transitioned
        old pre-OSIDB flaws without tasks are ignored unless force_creation is set
        """
        update_task = False
        transition_task = False

        if not self.task_key:
            # old pre-OSIDB flaws without tasks are ignored by default
            if force_creation or not self.meta_attr.get("bz_id"):
                update_task = True

        elif diff is not None:
            if any(field in diff.keys() for field in SYNC_REQUIRED_FIELDS):
                update_task = True

            if any(field in diff.keys() for field in TRANSITION_REQUIRED_FIELDS):
                transition_task = True

        if not update_task and not transition_task:
            return

        # switch of sync/async processing
        if JIRA_TASKMAN_ASYNCHRONOUS_SYNC:
            if update_task:
                JiraTaskSyncManager.check_for_reschedules()
                JiraTaskSyncManager.schedule(str(self.uuid))

            if transition_task:
                # workflow transition may result in ACL change
                self.adjust_acls(save=False)
                Flaw.objects.filter(uuid=self.uuid).update(
                    acl_read=self.acl_read,
                    acl_write=self.acl_write,
                )

                JiraTaskTransitionManager.check_for_reschedules()
                JiraTaskTransitionManager.schedule(str(self.uuid))

        else:
            if update_task:
                self._create_or_update_task(jira_token)

            if transition_task:
                # workflow transition may result in ACL change
                self.adjust_acls(save=False)
                Flaw.objects.filter(uuid=self.uuid).update(
                    acl_read=self.acl_read,
                    acl_write=self.acl_write,
                )

                self._transition_task(jira_token)

    def _create_or_update_task(self, jira_token=None):
        """
        create or update the Jira task of this flaw based on its existence
        """
        # import here to prevent cycles
        from apps.taskman.service import JiraTaskmanQuerier

        jtq = JiraTaskmanQuerier(token=jira_token)

        # creation
        if not self.task_key:
            self.task_key = jtq.create_or_update_task(self)
            self.workflow_state = WorkflowModel.WorkflowState.NEW
            Flaw.objects.filter(uuid=self.uuid).update(
                task_key=self.task_key,
                workflow_state=self.workflow_state,
            )
        else:
            jtq.create_or_update_task(self)

    def _transition_task(self, jira_token=None):
        """
        transition the Jira task of this flaw
        """
        # import here to prevent cycles
        from apps.taskman.service import JiraTaskmanQuerier

        jtq = JiraTaskmanQuerier(token=jira_token)

        jtq.transition_task(self)

    task_download_manager = models.ForeignKey(
        JiraTaskDownloadManager, null=True, blank=True, on_delete=models.SET_NULL
    )
    task_sync_manager = models.ForeignKey(
        JiraTaskSyncManager, null=True, blank=True, on_delete=models.SET_NULL
    )
    task_transition_manager = models.ForeignKey(
        JiraTaskTransitionManager, null=True, blank=True, on_delete=models.SET_NULL
    )
    bzsync_manager = models.ForeignKey(
        BZSyncManager, null=True, blank=True, on_delete=models.SET_NULL
    )
