import json
import logging
import re
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Union

import pghistory
from cvss import CVSS2, CVSS3, CVSS4, CVSSError
from django.contrib.auth.models import User
from django.contrib.postgres import fields
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import (
    SearchQuery,
    SearchRank,
    SearchVector,
    TrigramSimilarity,
)
from django.core.exceptions import (
    FieldDoesNotExist,
    ObjectDoesNotExist,
    ValidationError,
)
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from polymorphic.models import PolymorphicModel
from psqlextra.fields import HStoreField

from apps.bbsync.constants import (
    RHSCL_BTS_KEY,
    SYNC_FLAWS_TO_BZ,
    SYNC_FLAWS_TO_BZ_ASYNCHRONOUSLY,
    SYNC_TRACKERS_TO_BZ,
)
from apps.bbsync.mixins import BugzillaSyncMixin
from apps.bbsync.models import BugzillaComponent
from apps.exploits.mixins import AffectExploitExtensionMixin
from apps.exploits.query_sets import AffectQuerySetExploitExtension
from apps.taskman.constants import JIRA_TASKMAN_AUTO_SYNC_FLAW, SYNC_REQUIRED_FIELDS
from apps.taskman.mixins import JiraTaskSyncMixin
from apps.trackers.constants import SYNC_TO_JIRA
from apps.workflows.workflow import WorkflowFramework, WorkflowModel
from collectors.bzimport.constants import BZ_API_KEY, FLAW_PLACEHOLDER_KEYWORD

from .helpers import ps_update_stream_natural_keys
from .mixins import (
    ACLMixin,
    ACLMixinManager,
    Alert,
    AlertMixin,
    NullStrFieldsMixin,
    TrackingMixin,
    TrackingMixinManager,
    ValidateMixin,
)
from .sync_manager import (
    BZSyncManager,
    BZTrackerDownloadManager,
    BZTrackerLinkManager,
    FlawDownloadManager,
    JiraTrackerLinkManager,
)
from .validators import no_future_date, validate_cve_id, validate_cwe_id

logger = logging.getLogger(__name__)


def search_helper(
    queryset: models.QuerySet,
    field_names: Union[str, tuple],
    field_value: str,  # Three positional args are expected by django-filters, keyword args can be added if needed
):
    """
    Customize search filter and other logic for Postgres full-text search

    By default, Django uses the plainto_tsquery() Postgres function, which doesn't support search operators
    We override this with websearch_to_tsquery() which supports "quoted phrases" and -exclusions
    We also extend logic here to support weighting and ranking search results, based on which column is matched
    """
    query = SearchQuery(field_value, search_type="websearch")

    if field_names and field_names != "search":
        # Search only field(s) user provided, weighted equally
        if isinstance(field_names, str):
            # django-filters gives exactly one field name as str, other users give tuple of fields to search
            field_names = (field_names,)

        vector = SearchVector(*field_names)

    else:  # Empty tuple or 'search' (default from django-filters when field name not specified)
        # Search all Flaw text columns, weighted so title is most relevant
        # TODO: Add logic to make this more generic (for any model) instead of assuming we are searching Flaws
        # We could just search all fields, or get only text fields from a model dynamically
        # Logic to set weights makes this more complicated
        vector = (
            SearchVector("title", weight="A")
            + SearchVector("cve_id", weight="A")
            + SearchVector("comment_zero", weight="B")
            + SearchVector("cve_description", weight="C")
            + SearchVector("statement", weight="D")
        )

    # Allow searching CVEs by similarity instead of tokens like full-text search does.
    # Using tokens, the word 'securit' will not match with 'security', and 'CVE-2001-04'
    # will not match with 'CVE-2001-0414'. This behavior may be intended for text based fields, but
    # when searching for CVEs it's probably because the user forgot part of, or the order of, the numbers.
    similarity = TrigramSimilarity("cve_id", field_value)

    rank = SearchRank(vector, query, cover_density=True)
    # Consider proximity of matching terms when ranking

    return (
        queryset.annotate(rank=rank, similarity=similarity)
        # The similarity threshold of 0.7 has been found by trial and error to work best with CVEs
        .filter(Q(rank__gt=0) | Q(similarity__gt=0.7)).order_by("-rank")
    )
    # Add "rank" column to queryset based on search result relevance
    # Exclude results that don't match (rank 0)
    # Order remaining results from highest rank to lowest


class ComparableTextChoices(models.TextChoices):
    """
    extension of the models.TextChoices classes
    making them comparable with the standard operators

    the comparison order is defined simply by the
    top-down order in which the choices are written
    """

    @classmethod
    def get_choices(cls):
        """
        get processed choices
        """
        return [choice[0] for choice in cls.choices]

    @property
    def weight(self):
        """
        weight of the instance for the comparison
        defined by the order of the definition of the choices
        """
        return self.get_choices().index(str(self))

    def incomparable_with(self, other):
        """
        to ensure that that we are comparing the instances of the same type as
        comparing different types (even two ComparableTextChoices) is undefined
        """
        return type(self) is not type(other)

    def __hash__(self):
        return super().__hash__()

    def __eq__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self.weight == other.weight

    def __ne__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self.weight != other.weight

    def __lt__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self.weight < other.weight

    def __gt__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self.weight > other.weight

    def __le__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self == other or self.__lt__(other)

    def __ge__(self, other):
        if self.incomparable_with(other):
            return NotImplemented
        return self == other or self.__gt__(other)


class Impact(ComparableTextChoices):
    """allowable impact"""

    NOVALUE = ""
    LOW = "LOW"
    MODERATE = "MODERATE"
    IMPORTANT = "IMPORTANT"
    CRITICAL = "CRITICAL"


class FlawSource(models.TextChoices):
    """
    Enum to indicate where a Flaw was first reported.

    Whether the source is public or private can be determined by calling the
    is_public() method on any Enum member.
    """

    ADOBE = "ADOBE"
    APPLE = "APPLE"
    ASF = "ASF"  # (APACHE, APACHEANNOUNCE)
    BIND = "BIND"
    BK = "BK"
    BUGTRAQ = "BUGTRAQ"
    BUGZILLA = "BUGZILLA"
    CERT = "CERT"
    CERTFI = "CERTIFI"
    CORELABS = "CORELABS"
    CUSTOMER = "CUSTOMER"
    CVE = "CVE"
    DAILYDAVE = "DAILYDAVE"
    DEBIAN = "DEBIAN"
    DISTROS = "DISTROS"
    FEDORA = "FEDORA"
    FETCHMAIL = "FETCHMAIL"
    FREEDESKTOP = "FREEDESKTOP"  # FREEDESKTOP.ORG
    FREERADIUS = "FREERADIUS"
    FRSIRT = "FRSIRT"
    FULL_DISCLOSURE = "FULLDISCLOSURE"  # FULLDISC
    GAIM = "GAIM"
    GENTOO = "GENTOO"
    GENTOOBZ = "GENTOOBZ"
    GIT = "GIT"
    GNOME = "GNOME"
    GNUPG = "GNUPG"
    GOOGLE = "GOOGLE"
    HP = "HP"
    HW_VENDOR = "HW_VENDOR"  # HWVENDOR
    IBM = "IBM"
    IDEFENSE = "IDEFENSE"
    INTERNET = "INTERNET"
    ISC = "ISC"
    ISEC = "ISEC"
    IT = "IT"
    JBOSS = "JBOSS"
    JPCERT = "JPCERT"
    KERNELBUGZILLA = "KERNELBUGZILLA"
    KERNELSEC = "KERNELSEC"
    LKML = "LKML"
    LWN = "LWN"
    MACROMEDIA = "MACROMEDIA"
    MAGEIA = "MAGEIA"
    MAILINGLIST = "MAILINGLIST"
    MILW0RM = "MILW0RM"
    MIT = "MIT"
    MITRE = "MITRE"
    MOZILLA = "MOZILLA"
    MUTTDEV = "MUTTDEV"
    NETDEV = "NETDEV"
    NISCC = "NISCC"
    NOVALUE = ""
    NVD = "NVD"
    OCERT = "OCERT"
    OPENOFFICE = "OPENOFFICE"  # OPENOFFICE.ORG
    OPENSSL = "OPENSSL"
    OPENSUSE = "OPENSUSE"
    ORACLE = "ORACLE"
    OSS = "OSS"
    OSS_SECURITY = "OSSSECURITY"
    OSV = "OSV"
    PHP = "PHP"
    PIDGIN = "PIDGIN"
    POSTGRESQL = "POSTGRESQL"
    PRESS = "PRESS"
    REAL = "REAL"
    REDHAT = "REDHAT"
    RESEARCHER = "RESEARCHER"
    RT = "RT"
    SAMBA = "SAMBA"
    SECALERT = "SECALERT"
    SECUNIA = "SECUNIA"
    SECURITYFOCUS = "SECURITYFOCUS"
    SKO = "SKO"
    SQUID = "SQUID"
    SQUIRRELMAIL = "SQUIRRELMAIL"
    SUN = "SUN"
    SUNSOLVE = "SUNSOLVE"
    SUSE = "SUSE"
    TWITTER = "TWITTER"
    UBUNTU = "UBUNTU"
    UPSTREAM = "UPSTREAM"
    VENDOR_SEC = "VENDORSEC"
    VULNWATCH = "VULNWATCH"
    WIRESHARK = "WIRESHARK"
    XCHAT = "XCHAT"
    XEN = "XEN"
    XPDF = "XPDF"

    @property
    def private(self):
        return {
            # PRIVATE_SOURCES from SFM2
            self.ADOBE,
            self.APPLE,
            self.CERT,
            self.CUSTOMER,
            self.DISTROS,
            self.GOOGLE,
            self.HW_VENDOR,
            self.MOZILLA,
            self.OPENSSL,
            self.REDHAT,
            self.RESEARCHER,
            self.SECUNIA,
            self.UPSTREAM,
            self.XEN,
            self.VENDOR_SEC,
            self.SUN,
        }

    @property
    def ambiguous(self):
        return {
            self.DEBIAN,
            self.MAGEIA,
            self.GENTOO,
            self.SUSE,
            self.UBUNTU,
        }

    @property
    def public(self):
        return {
            self.ASF,
            self.BIND,
            self.BK,
            self.BUGTRAQ,
            self.BUGZILLA,
            self.CERTFI,
            self.CORELABS,
            self.CVE,
            self.DAILYDAVE,
            self.FEDORA,
            self.FETCHMAIL,
            self.FREEDESKTOP,
            self.FREERADIUS,
            self.FRSIRT,
            self.FULL_DISCLOSURE,
            self.GAIM,
            self.GENTOOBZ,
            self.GIT,
            self.GNOME,
            self.GNUPG,
            self.HP,
            self.IBM,
            self.IDEFENSE,
            self.INTERNET,
            self.ISC,
            self.ISEC,
            self.IT,
            self.JBOSS,
            self.JPCERT,
            self.KERNELBUGZILLA,
            self.KERNELSEC,
            self.LKML,
            self.LWN,
            self.MACROMEDIA,
            self.MAILINGLIST,
            self.MILW0RM,
            self.MIT,
            self.MITRE,
            self.MUTTDEV,
            self.NETDEV,
            self.NISCC,
            self.NOVALUE,
            self.OCERT,
            self.OPENOFFICE,
            self.OPENSUSE,
            self.ORACLE,
            self.OSS,
            self.OSS_SECURITY,
            self.PHP,
            self.PIDGIN,
            self.POSTGRESQL,
            self.PRESS,
            self.REAL,
            self.RT,
            self.SAMBA,
            self.SECALERT,
            self.SECURITYFOCUS,
            self.SKO,
            self.SQUID,
            self.SQUIRRELMAIL,
            self.SUNSOLVE,
            self.TWITTER,
            self.VULNWATCH,
            self.WIRESHARK,
            self.XCHAT,
            self.XPDF,
        }

    @property
    def allowed(self):
        return {
            self.ADOBE,
            self.APPLE,
            self.BUGTRAQ,
            self.CERT,
            self.CUSTOMER,
            self.CVE,
            self.DEBIAN,
            self.DISTROS,
            self.FULL_DISCLOSURE,
            self.GENTOO,
            self.GIT,
            self.GOOGLE,
            self.HW_VENDOR,
            self.INTERNET,
            self.LKML,
            self.MAGEIA,
            self.MOZILLA,
            self.OPENSSL,
            self.ORACLE,
            self.OSS_SECURITY,
            self.REDHAT,
            self.RESEARCHER,
            self.SECUNIA,
            self.SKO,
            self.SUN,
            self.SUSE,
            self.TWITTER,
            self.UBUNTU,
            self.UPSTREAM,
            self.VENDOR_SEC,
            self.XEN,
        }

    @property
    def from_snippet(self):
        return {
            self.NVD,
            self.OSV,
        }

    def is_private(self):
        """
        Returns True if the source is private, False otherwise.

        Note that the following sources can be both public and private:
        DEBIAN, MAGEIA, GENTOO, SUSE, UBUNTU
        """
        return self in (self.private | self.ambiguous)

    def is_public(self):
        """
        Returns True if the source is public, False otherwise.

        Note that the following sources can be both public and private:
        DEBIAN, MAGEIA, GENTOO, SUSE, UBUNTU
        """
        return self in (self.public | self.ambiguous)

    def is_allowed(self):
        """
        Returns True if the source is allowed (not historical), False otherwise.
        """
        return self in self.allowed

    def is_from_snippet(self):
        """
        Returns True if the source is Snippet, False otherwise.
        """
        return self in self.from_snippet


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

    # flaw severity, from srtnotes "impact"
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

    # if redhat cve-id then this is required, from srtnotes "statement"
    # eventually should compose up from affects
    statement = models.TextField(blank=True)

    # contains a single cwe-id or cwe relationships, from srtnotes "cwe"
    cwe_id = models.CharField(blank=True, max_length=255, validators=[validate_cwe_id])

    # date when embargo is to be lifted, from srtnotes "public"
    unembargo_dt = models.DateTimeField(null=True, blank=True)

    # reported source of flaw, from srtnotes "source"
    source = models.CharField(choices=FlawSource.choices, max_length=500, blank=True)

    # reported date, from srtnotes "reported"
    reported_dt = models.DateTimeField(
        null=True, blank=True, validators=[no_future_date]
    )

    # mitigation to apply if the final fix is not available, from srtnotes "mitigation"
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
        Validate that a Flaw that is Major Incident complies with the following:
        * has a mitigation
        * has a statement
        * has a cve_description
        * requires_cve_description is APPROVED
        * has exactly one article
        """
        if self.major_incident_state != Flaw.FlawMajorIncident.APPROVED:
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
        if self._state.adding:
            return

        old_flaw = Flaw.objects.get(pk=self.pk)
        was_high_impact = old_flaw.impact in [
            Impact.CRITICAL,
            Impact.IMPORTANT,
        ] or old_flaw.major_incident_state in [
            Flaw.FlawMajorIncident.APPROVED,
            Flaw.FlawMajorIncident.CISA_APPROVED,
        ]
        is_high_impact = self.impact in [
            Impact.CRITICAL,
            Impact.IMPORTANT,
        ] or self.major_incident_state in [
            Flaw.FlawMajorIncident.APPROVED,
            Flaw.FlawMajorIncident.CISA_APPROVED,
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
        return not self.affects.exclude(
            affectedness=Affect.AffectAffectedness.NOTAFFECTED
        ).exists()

    @property
    def affects_resolved(self):
        """check that all affects have resolution"""
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

    def bzsync(self, *args, bz_api_key, **kwargs):
        """
        Bugzilla sync of the Flaw instance
        """
        if not SYNC_FLAWS_TO_BZ:
            # up until now the parent save methods run in sequence of
            # 1) TrackingMixin with auto-timestamps on
            # 2) JiraTaskSyncMixin syncing the task if enabled
            # 3) BugzillaSyncMixin running the validations
            # so we do not need to run any other mixins
            kwargs.pop("raise_validation_error", None)
            super(ValidateMixin, self).save(*args, **kwargs)
            return

        # switch of sync/async processing
        if SYNC_FLAWS_TO_BZ_ASYNCHRONOUSLY:
            # Process the bzsync asynchronously
            BZSyncManager.check_for_reschedules()
            kwargs["bz_api_key"] = bz_api_key
            BZSyncManager.schedule(str(self.uuid), *args, **kwargs)
        else:
            # imports here to prevent cycles
            from apps.bbsync.save import FlawBugzillaSaver
            from collectors.bzimport.collectors import FlawCollector

            # sync to Bugzilla
            bs = FlawBugzillaSaver(self, bz_api_key)
            flaw_instance = bs.save()
            kwargs[
                "auto_timestamps"
            ] = False  # the timestamps will be get from Bugzilla
            kwargs["raise_validation_error"] = False  # the validations were already run
            # save in case a new Bugzilla ID was obtained
            flaw_instance.save(no_alerts=True, *args, **kwargs)

            # fetch from Bugzilla
            fc = FlawCollector()
            fc.no_alerts = True
            fc.sync_flaw(flaw_instance.bz_id)
            # Make sure the flaw instance has the latest data
            flaw_instance.refresh_from_db()

    def _perform_bzsync(self, *args, bz_api_key, **kwargs):
        """
        Helper function that contains the actual logic of the Bugzilla sync,
        without additional checks - only the one-way sync to Bugzilla.
        """
        # imports here to prevent cycles
        from apps.bbsync.save import FlawBugzillaSaver

        creating = self.bz_id is None

        # sync to Bugzilla
        bs = FlawBugzillaSaver(self, bz_api_key)  # prepare data for save to BZ
        self = bs.save()  # actually send to BZ (but not save to DB)

        if creating:
            # Save bz_id to DB
            kwargs["auto_timestamps"] = False  # no timestamps changes on save to BZ
            kwargs["raise_validation_error"] = False  # the validations were already run
            # save in case a new Bugzilla ID was obtained
            # Instead of self.save(*args, **kwargs), just update the single field to avoid
            # race conditions.
            self.save(*args, update_fields=["meta_attr"], **kwargs)

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
    bzsync_manager = models.ForeignKey(
        BZSyncManager, null=True, blank=True, on_delete=models.CASCADE
    )


class Snippet(ACLMixin, AlertMixin, TrackingMixin):
    """
    Snippet stores data scraped by collectors. One or more snippets can either be linked
    to an existing flaw or serve as a source for a new flaw.
    """

    class Source(models.TextChoices):
        """
        Sources should match collector names (i.e. "NVD" corresponds to NVD collector).
        This class should be extended everytime a new collector is introduced.
        """

        NVD = "NVD"
        OSV = "OSV"

    def save(self, *args, **kwargs):
        # set internal ACLs
        self.set_internal()
        super().save(*args, **kwargs)

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # A unique ID of this snippet as it is defined in the external data source where the
    # snippet was collected from.
    external_id = models.CharField(max_length=200)

    source = models.CharField(choices=Source.choices, max_length=100)

    # if possible, these values should correspond to attributes in Flaw
    content = models.JSONField(default=dict)

    # one flaw can have many snippets
    flaw = models.ForeignKey(
        Flaw, on_delete=models.CASCADE, related_name="snippets", blank=True, null=True
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                name="unique_snippets", fields=["source", "external_id"]
            ),
        ]

    def convert_snippet_to_flaw(self, *args, **kwargs) -> Union[Flaw, None]:
        """
        Creates a new flaw from the snippet's content if a flaw with the given cve_id/external_id
        does not exist, and links them together. If a flaw already exists and does not
        contain the snippet of the current source, the snippet will be linked to it.

        Returns a flaw if it was newly created, None otherwise.
        """
        # unlike NVD, OSV may not always have a cve_id, so we have to check external_id as well
        cve_id = self.content["cve_id"]
        external_id = self.external_id
        created_flaw = None

        if cve_id and (f := Flaw.objects.filter(cve_id=cve_id)):
            flaw = f.first()
        elif f := Flaw.objects.filter(meta_attr__external_ids__contains=external_id):
            flaw = f.first()
        else:
            flaw = self._create_flaw(*args, **kwargs)
            created_flaw = flaw

        # links either a newly created or an already existing flaw to the snippet
        self.flaw = flaw
        self.save()

        return created_flaw

    def _create_flaw(self, *args, **kwargs) -> Flaw:
        """
        Internal helper function to create a new flaw from the snippet's content. Any data
        from the snippet's content that does not match the fields in Flaw will be ignored.

        Returns a newly created flaw.
        """
        main_model = {}
        related_models = {}

        for key, value in self.content.items():
            try:
                field = Flaw._meta.get_field(key)

                if field.is_relation:
                    related_models[field.related_model] = value
                elif field.model not in main_model:
                    main_model[field.model] = {key: value}
                else:
                    main_model[field.model].update({key: value})
            except FieldDoesNotExist:
                # anything that does not match the fields in Flaw will be ignored
                pass

        shared_acl = {"acl_read": self.acl_read, "acl_write": self.acl_write}
        # ensure that a flaw always contains external id (even if BZ sync is disabled)
        shared_flaw = shared_acl | {"meta_attr": {"external_ids": self.external_id}}

        # Flaw model has to be created first
        model, data = [i for i in main_model.items()][0]
        flaw = model(**data, **shared_flaw)
        flaw.save(raise_validation_error=False)
        # reported_dt is set according to created_dt, which is set after flaw.save()
        flaw.reported_dt = flaw.created_dt

        # creates related models (e.g. FlawCVSS)
        for model, list_of_data in related_models.items():
            for data in list_of_data:
                related_model = model(flaw=flaw, **data, **shared_acl)
                related_model.save()

        # link newly created flaw to this snippet
        self.flaw = flaw
        self.save()

        # keep the save to Jira and BZ separate because BZ can be done asynchronously
        # (BZ token is passed directly, but Jira token is in kwargs)
        flaw.save(raise_validation_error=False, *args, **kwargs)
        flaw.save(bz_api_key=BZ_API_KEY, raise_validation_error=False, *args)

        return Flaw.objects.get(uuid=flaw.uuid)

    def _validate_acl_identical_to_parent_flaw(self, **kwargs) -> None:
        """
        No ACL validations are run for snippet's flaw as its ACLs can be different.
        However, snippet should always have internal ACLs.
        """
        pass


class AffectManager(ACLMixinManager, TrackingMixinManager):
    """affect manager"""

    @staticmethod
    def create_affect(flaw, ps_module, ps_component, **extra_fields):
        """return a new affect or update an existing affect without saving"""

        try:
            affect = Affect.objects.get(
                flaw=flaw, ps_module=ps_module, ps_component=ps_component
            )
            for attr, value in extra_fields.items():
                setattr(affect, attr, value)
            return affect
        except ObjectDoesNotExist:
            return Affect(
                flaw=flaw,
                ps_module=ps_module,
                ps_component=ps_component,
                **extra_fields,
            )

    @staticmethod
    def fts_search(q):
        """full text search using postgres FTS via django.contrib.postgres"""
        fields_to_search = (
            "ps_component",
            "ps_module",
            "resolution",
            "affectedness",
            "type",
        )
        return search_helper(Affect.objects.get_queryset(), fields_to_search, q)
        # Search Affect fields specified with equal weights
        # If search has no results, this will now return an empty queryset


@pghistory.track(
    pghistory.InsertEvent(),
    pghistory.UpdateEvent(),
    pghistory.DeleteEvent(),
    exclude="meta_attr,_alerts",
    model_name="AffectAudit",
)
class Affect(
    AlertMixin,
    ACLMixin,
    AffectExploitExtensionMixin,
    BugzillaSyncMixin,
    NullStrFieldsMixin,
    TrackingMixin,
):
    """affect model definition"""

    class AffectAffectedness(models.TextChoices):
        """allowable states"""

        NOVALUE = "", _("No value")
        NEW = "NEW", _("Unknown")  # resolution is optional
        AFFECTED = "AFFECTED", _("Affected")  # always need a resolution
        NOTAFFECTED = "NOTAFFECTED", _("Not affected")  # resolution can be novalue

    class AffectResolution(models.TextChoices):
        """allowable resolution"""

        NOVALUE = ""
        FIX = "FIX"
        DEFER = "DEFER"
        WONTFIX = "WONTFIX"
        OOSS = "OOSS"
        DELEGATED = "DELEGATED"
        WONTREPORT = "WONTREPORT"

    class AffectFix(models.TextChoices):
        AFFECTED = "AFFECTED"
        NOTAFFECTED = "NOTAFFECTED"
        WONTFIX = "WONTFIX"
        OOSS = "OOSS"
        DEFER = "DEFER"

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # affectedness:resolution status
    affectedness = models.CharField(
        choices=AffectAffectedness.choices,
        default=AffectAffectedness.NEW,
        max_length=100,
        blank=True,
    )
    resolution = models.CharField(
        choices=AffectResolution.choices,
        default=AffectResolution.NOVALUE,
        max_length=100,
        blank=True,
    )

    # from srtnotes affects/ps_module
    ps_module = models.CharField(max_length=100)

    # from srtnotes affects/ps_components
    # the length 255 does not have any special meaning in Postgres
    # but it is the maximum SFM2 value so let us just keep parity for now
    # to fix https://issues.redhat.com/browse/OSIDB-635
    ps_component = models.CharField(max_length=255)

    # from srtnotes affects/impact
    impact = models.CharField(choices=Impact.choices, max_length=20, blank=True)

    # non operational meta data
    meta_attr = HStoreField(default=dict)

    # A Flaw can have many Affects
    flaw = models.ForeignKey(
        Flaw, null=True, on_delete=models.CASCADE, related_name="affects"
    )

    class Meta:
        """define meta"""

        unique_together = ("flaw", "ps_module", "ps_component")
        ordering = (
            "created_dt",
            "uuid",
        )
        verbose_name = "Affect"
        indexes = TrackingMixin.Meta.indexes + [
            models.Index(fields=["flaw", "ps_module"]),
            models.Index(fields=["flaw", "ps_component"]),
            GinIndex(fields=["acl_read"]),
        ]

    # objects = AffectManager()
    objects = AffectManager.from_queryset(AffectQuerySetExploitExtension)()

    def __str__(self):
        return str(self.uuid)

    def _validate_ps_module_old_flaw(self, **kwargs):
        """
        Checks that an affect from an older flaw contains a valid ps_module.

        This method will only generate an alert and will not raise a ValidationError,
        this is because there is legacy data in external systems that we pull from
        (i.e. BZ) that worked under a different system (ps_update_stream instead of
        ps_module for affects) and thus raising a ValidationError would make legacy
        flaws unupdatable.
        """
        bz_id = self.flaw.meta_attr.get("bz_id")
        if bz_id and int(bz_id) <= BZ_ID_SENTINEL:
            if self.is_unknown:
                self.alert(
                    "old_flaw_affect_ps_module",
                    f"{self.ps_module} is not a valid ps_module "
                    f"for flaw with bz_id {bz_id}.",
                    **kwargs,
                )

    def _validate_ps_module_new_flaw(self, **kwargs):
        """
        Checks that an affect from a newer flaw contains a valid ps_module.

        This method will raise a ValidationError if the ps_module being passed
        is not a valid one, this is the standard for "newer" flaws and violation
        of this constraint by newer flaws should outright block the creation or
        update of an affect.
        """
        bz_id = self.flaw.meta_attr.get("bz_id")
        if bz_id and int(bz_id) > BZ_ID_SENTINEL:
            if self.is_unknown:
                raise ValidationError(
                    f"{self.ps_module} is not a valid ps_module "
                    f"for flaw with bz_id {bz_id}."
                )

    def _validate_sofware_collection(self, **kwargs):
        """
        Check that all RHSCL components in flaw's affects start with a valid collection.
        """
        if not self.is_rhscl or self.ps_component in COMPONENTS_WITHOUT_COLLECTION:
            return

        streams = PsUpdateStream.objects.filter(ps_module__name=self.ps_module)
        collections = streams.values_list("collections", flat=True).all()

        is_valid_component = False
        is_meta_package = False
        for collection in collections:
            for component in collection:
                if self.ps_component == component:
                    is_meta_package = True
                if self.ps_component.startswith(component + "-"):
                    is_valid_component = True

        is_valid_component = is_valid_component and not is_meta_package

        if is_meta_package:
            self.alert(
                "flaw_affects_rhscl_collection_only",
                f"PSComponent {self.ps_component} for {self.ps_module} indicates collection "
                "meta-package rather than a specific component in the collection",
                **kwargs,
            )

        if not is_valid_component:
            self.alert(
                "flaw_affects_rhscl_invalid_collection",
                f"PSComponent {self.ps_component} for {self.ps_module} "
                "does not match any valid collection",
                **kwargs,
            )

    def _validate_historical_affectedness_resolution(self, **kwargs):
        """
        Alerts that an old flaw has an affectedness/resolution combination that is now invalid,
        but was valid in the past.
        """
        if (
            self.resolution
            in AFFECTEDNESS_HISTORICAL_VALID_RESOLUTIONS[self.affectedness]
        ):
            # Don't allow new records with historical combinations, or changing old records
            # to an invalid combination
            old_affect = (
                Affect.objects.get(uuid=self.uuid) if not self._state.adding else None
            )
            if (
                self._state.adding
                or self.affectedness != old_affect.affectedness
                or self.resolution != old_affect.resolution
            ):
                raise ValidationError(
                    f"Affect ({self.uuid}) for {self.ps_module}/{self.ps_component} has an invalid "
                    f"affectedness/resolution combination: {self.resolution} is not a valid resolution "
                    f"for {self.affectedness}."
                )

            # If modifying something else from a record with an invalid combination, e.g. the
            # impact, throw an alert
            self.alert(
                "flaw_historical_affect_status",
                f"Affect ({self.uuid}) for {self.ps_module}/{self.ps_component} has a "
                "historical affectedness/resolution combination which is not valid anymore: "
                f"{self.resolution} is not a valid resolution for {self.affectedness}.",
                **kwargs,
            )

    def _validate_affect_status_resolution(self, **kwargs):
        """
        Validates that affected products have a valid combination (currently or historically)
        of affectedness and resolution.
        """
        if (
            self.resolution not in AFFECTEDNESS_VALID_RESOLUTIONS[self.affectedness]
            and self.resolution
            not in AFFECTEDNESS_HISTORICAL_VALID_RESOLUTIONS[self.affectedness]
        ):
            raise ValidationError(
                f"Affect ({self.uuid}) for {self.ps_module}/{self.ps_component} has an invalid "
                f"affectedness/resolution combination: {self.resolution} is not a valid resolution "
                f"for {self.affectedness}."
            )

    def _validate_notaffected_open_tracker(self, **kwargs):
        """
        Check whether notaffected products have open trackers.
        """
        if (
            self.affectedness == Affect.AffectAffectedness.NOTAFFECTED
            and self.trackers.exclude(
                status__iexact="CLOSED"
            ).exists()  # see tracker.is_closed
        ):
            raise ValidationError(
                f"Affect ({self.uuid}) for {self.ps_module}/{self.ps_component} is marked as "
                "NOTAFFECTED but has open tracker(s).",
            )

    def _validate_ooss_open_tracker(self, **kwargs):
        """
        Check whether out of support scope products have open trackers.
        """
        if (
            self.resolution == Affect.AffectResolution.OOSS
            and self.trackers.exclude(
                status__iexact="CLOSED"
            ).exists()  # see tracker.is_closed
        ):
            raise ValidationError(
                f"Affect ({self.uuid}) for {self.ps_module}/{self.ps_component} is marked as "
                "OOSS but has open tracker(s).",
            )

    def _validate_wontfix_open_tracker(self, **kwargs):
        """
        Check whether wontfix affects have open trackers.
        """
        if (
            self.resolution == Affect.AffectResolution.WONTFIX
            and self.trackers.exclude(
                status__iexact="CLOSED"
            ).exists()  # see tracker.is_closed
        ):
            raise ValidationError(
                f"Affect ({self.uuid}) for {self.ps_module}/{self.ps_component} is marked as "
                "WONTFIX but has open tracker(s).",
            )

    def _validate_unknown_component(self, **kwargs):
        """
        Alerts that a flaw affects a component not tracked in Bugzilla.
        Alternatively, the PSComponent should have an override set in Product Definitions.
        The used PSComponent is either misspelled or the override is missing.
        """

        if not self.ps_component:
            return

        ps_module = PsModule.objects.filter(name=self.ps_module).first()
        if not ps_module:
            # unknown PSModule; should be checked in other function
            return

        if ps_module.default_component:
            # PSModule has a default component set; assume all as valid
            return

        if self.is_rhscl:
            cc_affect = RHSCLAffectCCBuilder(affect=self, embargoed=self.is_embargoed)
            _, component = cc_affect.collection_component()
        else:
            cc_affect = AffectCCBuilder(affect=self, embargoed=self.is_embargoed)
            component = cc_affect.ps2bz_component()

        if not cc_affect.is_bugzilla:
            # only Bugzilla BTS is supported
            return

        if ps_module.component_overrides and component in ps_module.component_overrides:
            # PSComponent is being overridden for BTS; assume its correct
            return

        if not BugzillaComponent.objects.filter(name=component).exists():
            # Components for BTS key does not exist; maybe cache is not populated yet.
            # Instead of raising warning for all flaw bugs when metadata are not
            # cache, we will stay quiet.
            return

        bts_component = BugzillaComponent.objects.filter(
            name=component, product__name=ps_module.bts_key
        )
        if not bts_component.exists():
            alert_text = (
                f'Component "{component}" for {self.ps_module} did not match BTS component '
                f"(in {ps_module.bts_name}) nor component from Product Definitions"
            )
            self.alert(
                "flaw_affects_unknown_component",
                alert_text,
                **kwargs,
            )

    def _validate_wontreport_products(self, **kwargs):
        """
        Validate that wontreport resolution only can be used for
        products associated with services.
        """
        if self.resolution == Affect.AffectResolution.WONTREPORT:
            ps_module = PsModule.objects.filter(name=self.ps_module).first()
            if (
                not ps_module
                or ps_module.ps_product.short_name not in SERVICES_PRODUCTS
            ):
                raise ValidationError(
                    f"Affect ({self.uuid}) for {self.ps_module}/{self.ps_component} is marked as WONTREPORT, "
                    f"which can only be used for service products."
                )

    def _validate_wontreport_severity(self, **kwargs):
        """
        Validate that wontreport only can be used for
        low or moderate severity flaws.
        """
        if (
            self.resolution == Affect.AffectResolution.WONTREPORT
            and self.impact not in [Impact.LOW, Impact.MODERATE]
        ):
            raise ValidationError(
                f"Affect ({self.uuid}) for {self.ps_module}/{self.ps_component} has impact {self.impact} "
                f"and is marked as WONTREPORT, which can only be used with low or moderate impact."
            )

    def _validate_special_consideration_flaw(self, **kwargs):
        """
        Checks that a flaw affecting special consideration package(s) has both
        cve_description and statement
        """
        if not self.flaw or (self.flaw.cve_description and self.flaw.statement):
            return

        affected_special_consideration_package = (
            SpecialConsiderationPackage.objects.filter(name=self.ps_component)
        ).values_list("name", flat=True)
        if affected_special_consideration_package.exists():
            if not self.flaw.cve_description:
                self.flaw.alert(
                    "special_consideration_flaw_missing_cve_description",
                    "Flaw affecting special consideration package "
                    f"{affected_special_consideration_package} is missing cve_description.",
                )
            if not self.flaw.statement:
                self.flaw.alert(
                    "special_consideration_flaw_missing_statement",
                    "Flaw affecting special consideration package "
                    f"{affected_special_consideration_package} is missing statement.",
                )

    @property
    def aggregated_impact(self):
        """
        this property equals Flaw's impact if the Affect's impact is blank, or
        equals the Affect's impact if the Affect's impact is not blank
        """
        if not self.impact:
            return Impact(self.flaw.impact)
        else:
            return Impact(self.impact)

    @property
    def delegated_resolution(self):
        """affect delegated resolution based on resolutions of related trackers"""
        if not (
            self.affectedness == Affect.AffectAffectedness.AFFECTED
            and self.resolution == Affect.AffectResolution.DELEGATED
        ):
            return None

        # exclude the trackers closed as duplicate or migrated from Bugzilla
        trackers = self.trackers.exclude(resolution__iregex=r"(duplicate|migrated)")
        if not trackers:
            return Affect.AffectFix.AFFECTED

        statuses = [tracker.fix_state for tracker in trackers]
        # order is **very** important here, if there are multiple trackers
        # the order of these statuses determines which tracker status takes
        # precedence over all the rest, meaning that if one tracker is affected
        # and another is not affected, the overall affect delegated_resolution
        # will be affected and not notaffected.
        for status in (
            Affect.AffectFix.AFFECTED,
            Affect.AffectFix.WONTFIX,
            Affect.AffectFix.OOSS,
            Affect.AffectFix.DEFER,
            Affect.AffectFix.NOTAFFECTED,
        ):
            if status in statuses:
                return status

        # We don't know. Maybe none of the trackers have a valid resolution; default to "Affected".
        logger.error("How did we get here??? %s, %s", trackers, statuses)

        return Affect.AffectFix.AFFECTED

    @property
    def is_community(self) -> bool:
        """
        check and return whether the given affect is community one
        """
        return PsModule.objects.filter(
            name=self.ps_module, ps_product__business_unit="Community"
        ).exists()

    @property
    def is_compliance_priority(self) -> bool:
        """
        Check and return whether this affect module and component combination is compliance
        priority which is defined in PS constants repo in compliance_priority.yml.

        Compliance priority is always False for LOW impact.

        Note that stream is not evaluated by this property. Therefore, this property
        is not useful for evaluating SLA, but useful for computing which streams to
        file trackers for. Use Tracker.is_compliance_priority for SLA calculations.
        """
        if self.aggregated_impact == Impact.LOW:
            return False
        compliance_priority = CompliancePriority.objects.filter(
            ps_module=self.ps_module
        )
        if not compliance_priority.exists():
            return False
        compliance_components = compliance_priority.first().components
        if not compliance_components:
            # Empty list of components in compliance_components.yml means all components are priority.
            return True
        return self.ps_component in compliance_components

    @property
    def is_notaffected(self) -> bool:
        """
        check and return whether the given affect is set as not affected or not to be fixed
        """
        return (
            self.affectedness == Affect.AffectFix.NOTAFFECTED
            or self.resolution == Affect.AffectResolution.WONTFIX
        )

    @property
    def is_rhscl(self) -> bool:
        """
        check and return whether the given affect is RHSCL one
        """
        return PsModule.objects.filter(
            name=self.ps_module, bts_key=RHSCL_BTS_KEY
        ).exists()

    @property
    def is_unknown(self) -> bool:
        """
        check and return whether the given affect has unknown PS module
        """
        return not PsModule.objects.filter(name=self.ps_module).exists()

    @property
    def ps_product(self):
        ps_module = PsModule.objects.filter(name=self.ps_module).first()
        if not ps_module:
            return None
        return ps_module.ps_product.name

    def bzsync(self, *args, bz_api_key, **kwargs):
        """
        Bugzilla sync of the Affect instance
        """
        self.save()
        # Affect needs to be synced through flaw
        self.flaw.save(*args, bz_api_key=bz_api_key, **kwargs)


class FlawCVSSManager(ACLMixinManager, TrackingMixinManager):
    @staticmethod
    def create_cvss(flaw, issuer, version, **extra_fields):
        """return a new CVSS or update an existing CVSS without saving"""

        try:
            cvss = FlawCVSS.objects.get(flaw=flaw, issuer=issuer, version=version)

            for attr, value in extra_fields.items():
                setattr(cvss, attr, value)
            return cvss

        except ObjectDoesNotExist:
            return FlawCVSS(flaw=flaw, issuer=issuer, version=version, **extra_fields)


class AffectCVSSManager(ACLMixinManager, TrackingMixinManager):
    @staticmethod
    def create_cvss(affect, issuer, version, **extra_fields):
        """return a new CVSS or update an existing CVSS without saving"""

        try:
            cvss = AffectCVSS.objects.get(affect=affect, issuer=issuer, version=version)
            for attr, value in extra_fields.items():
                setattr(cvss, attr, value)
            return cvss

        except ObjectDoesNotExist:
            return AffectCVSS(
                affect=affect, issuer=issuer, version=version, **extra_fields
            )


class CVSS(AlertMixin, ACLMixin, BugzillaSyncMixin, NullStrFieldsMixin, TrackingMixin):
    class CVSSVersion(models.TextChoices):
        VERSION2 = "V2", "version 2"
        VERSION3 = "V3", "version 3"
        VERSION4 = "V4", "version 4"

    class CVSSIssuer(models.TextChoices):
        REDHAT = "RH", "Red Hat"
        NIST = "NIST", "NIST"
        OSV = "OSV", "OSV"

    CVSS_HANDLES = {
        CVSSVersion.VERSION2: CVSS2,
        CVSSVersion.VERSION3: CVSS3,
        CVSSVersion.VERSION4: CVSS4,
    }

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    vector = models.CharField(max_length=100, blank=False)

    version = models.CharField(choices=CVSSVersion.choices, max_length=10)

    issuer = models.CharField(choices=CVSSIssuer.choices, max_length=16)

    comment = models.TextField(blank=True)

    # populated by the pre_save signal
    score = models.FloatField(default=0)

    def __str__(self):
        return f"{self.score}/{self.vector}"

    @property
    def full_version(self):
        """Full name of the CVSS version."""
        return f"CVSS{self.version[1:]}"

    @property
    def cvss_object(self):
        """
        CVSS object from CVSS library parsed from the vector.
        """
        cvss_handle = self.CVSS_HANDLES[self.version]
        return cvss_handle(self.vector)

    def _validate_cvss_string(self, **kwargs):
        """
        Use the cvss library to validate the CVSS vector string.
        """
        try:
            self.cvss_object
        except CVSSError as e:
            raise ValidationError(
                f"Invalid CVSS: Malformed {self.full_version} string: {e}"
            )

    def _validate_cvss_comment(self, **kwargs):
        """
        For non-Red-Hat-issued CVSSs, the comment attribute should be blank.
        """
        if self.comment and self.issuer != self.CVSSIssuer.REDHAT:
            raise ValidationError(
                "CVSS comment can be set only for CVSSs issued by Red Hat."
            )

    class Meta:
        abstract = True


class FlawCVSS(CVSS):
    flaw = models.ForeignKey(
        Flaw, on_delete=models.CASCADE, blank=True, related_name="cvss_scores"
    )

    objects = FlawCVSSManager()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["flaw", "version", "issuer"], name="unique CVSS of a Flaw"
            ),
        ]
        indexes = TrackingMixin.Meta.indexes + [
            GinIndex(fields=["acl_read"]),
        ]

    def bzsync(self, *args, bz_api_key, **kwargs):
        """
        Bugzilla sync of the FlawCVSS instance
        """
        self.save()
        # FlawCVSS needs to be synced through flaw
        self.flaw.save(*args, bz_api_key=bz_api_key, **kwargs)


class AffectCVSS(CVSS):
    affect = models.ForeignKey(
        Affect, on_delete=models.CASCADE, blank=True, related_name="cvss_scores"
    )

    objects = AffectCVSSManager()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["affect", "version", "issuer"], name="unique CVSS of an Affect"
            ),
        ]
        indexes = TrackingMixin.Meta.indexes + [
            GinIndex(fields=["acl_read"]),
        ]

    def bzsync(self, *args, bz_api_key, **kwargs):
        """
        Bugzilla sync of the AffectCVSS instance
        """
        self.save()
        # AffectCVSS needs to be synced through affect
        self.affect.save(*args, bz_api_key=bz_api_key, **kwargs)


class TrackerManager(ACLMixinManager, TrackingMixinManager):
    """tracker manager"""

    @staticmethod
    def create_tracker(
        affect, external_system_id, _type, raise_validation_error=True, **extra_fields
    ):
        """return a new tracker or update an existing tracker"""
        try:
            tracker = Tracker.objects.get(
                external_system_id=external_system_id, type=_type
            )
            for attr, value in extra_fields.items():
                setattr(tracker, attr, value)
        except ObjectDoesNotExist:
            tracker = Tracker(
                external_system_id=external_system_id,
                type=_type,
                **extra_fields,
            )
            # must save, otherwise assigning affects won't work (no pk)
            # this is probably why before the affects were not being added
            # to newly created trackers
            tracker.save(raise_validation_error=raise_validation_error)
        if affect is not None:
            tracker.affects.add(affect)
            tracker.save(raise_validation_error=raise_validation_error)  # revalidate
        return tracker


class Tracker(AlertMixin, TrackingMixin, NullStrFieldsMixin, ACLMixin):
    """tracker model definition"""

    class TrackerType(models.TextChoices):
        """allowable bts name"""

        # NOTE: when moving or renaming this enum, please check and modify
        # config/settings.py::SPECTACULAR_SETTINGS::ENUM_NAME_OVERRIDES accordingly

        JIRA = "JIRA"
        BUGZILLA = "BUGZILLA"

    # mapping to product definitions BTS naming
    TYPE2BTS = {
        TrackerType.BUGZILLA: "bugzilla",
        TrackerType.JIRA: "jboss",
    }
    # plus opposite direction mapping
    BTS2TYPE = {b: t for t, b in TYPE2BTS.items()}

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # type
    type = models.CharField(choices=TrackerType.choices, max_length=100)

    # key
    # may be empty during the creation in an external system
    external_system_id = models.CharField(max_length=100, blank=True)

    # BTS status:resolution context
    # The values are dependent on the BTS.
    # Blank on creation until first jiraffe sync from Jira.
    status = models.CharField(max_length=100, blank=True)
    resolution = models.CharField(max_length=100, blank=True)
    ps_update_stream = models.CharField(max_length=100, blank=True)
    bts_updated_dt = models.DateTimeField(null=True, blank=True)

    # non operational meta data
    meta_attr = HStoreField(default=dict)

    # An Affect can have many trackers, and a tracker can track multiple flaw/affects
    affects = models.ManyToManyField(Affect, related_name="trackers", blank=True)

    class Meta:
        """define meta"""

        verbose_name = "Tracker"
        ordering = (
            "created_dt",
            "uuid",
        )
        constraints = [
            models.UniqueConstraint(
                fields=["type", "external_system_id"],
                condition=~Q(external_system_id=""),  # Only applies to non-empty keys
                name="unique_external_system_id",
            )
        ]

        indexes = TrackingMixin.Meta.indexes + [
            models.Index(fields=["external_system_id"]),
            GinIndex(fields=["acl_read"]),
        ]

    objects = TrackerManager()

    def __str__(self):
        return str(self.uuid)

    def save(self, *args, bz_api_key=None, jira_token=None, **kwargs):
        """
        save the tracker by storing to the backend and fetching back

        when neither Bugzilla API key and nor Jira token is provided
        it is considered to be a call done by a collector or test
        and thus we perform just regular save

        the backend sync is also conditional based on environment variables
        """
        # imports here to prevent cycles
        from apps.trackers.save import TrackerSaver
        from collectors.bzimport.collectors import BugzillaTrackerCollector
        from collectors.jiraffe.collectors import JiraTrackerCollector

        # check Bugzilla conditions are met
        if (
            SYNC_TRACKERS_TO_BZ
            and bz_api_key is not None
            and self.type == self.TrackerType.BUGZILLA
        ):
            # sync to Bugzilla
            tracker_instance = TrackerSaver(self, bz_api_key=bz_api_key).save()
            # save in case a new Bugzilla ID was obtained
            # so the tracker is later matched in BZ import

            # the validations were already run
            kwargs["raise_validation_error"] = False
            kwargs["no_alerts"] = True
            tracker_instance.save(*args, **kwargs)
            # fetch from Bugzilla
            btc = BugzillaTrackerCollector()
            btc.no_alerts = True
            btc.sync_tracker(tracker_instance.external_system_id)
            BZTrackerLinkManager.link_tracker_with_affects(
                tracker_instance.external_system_id
            )

        # check Jira conditions are met
        elif (
            SYNC_TO_JIRA
            and jira_token is not None
            and self.type == self.TrackerType.JIRA
        ):
            # sync to Jira
            tracker_instance = TrackerSaver(self, jira_token=jira_token).save()
            # save in case a new Jira ID was obtained
            # so the flaw is later matched in Jiraffe sync

            # the validations were already run
            kwargs["raise_validation_error"] = False
            kwargs["no_alerts"] = True
            tracker_instance.save(*args, **kwargs)
            # fetch from Jira
            jtc = JiraTrackerCollector()
            jtc.no_alerts = True
            jtc.collect(tracker_instance.external_system_id)
            JiraTrackerLinkManager.link_tracker_with_affects(
                tracker_instance.external_system_id
            )

        # regular save otherwise
        else:
            super().save(*args, **kwargs)

    def _validate_tracker_affect(self, **kwargs):
        """
        check that the tracker is associated with an affect
        """
        # there are no references before the first save to DB
        if self._state.adding:
            return

        if not self.affects.exists():
            raise ValidationError("Tracker must be associated with an affect")

    def _validate_tracker_ps_module(self, **kwargs):
        """
        check that the tracker is associated with a valid PS module
        """
        if not self.affects.exists():
            return

        if not PsModule.objects.filter(name=self.affects.first().ps_module):
            raise ValidationError("Tracker must be associated with a valid PS module")

    def _validate_tracker_ps_update_stream(self, **kwargs):
        """
        check that the tracker is associated with a valid PS update stream
        """
        if not PsUpdateStream.objects.filter(name=self.ps_update_stream):
            raise ValidationError(
                "Tracker must be associated with a valid PS update stream"
            )

    def _validate_tracker_flaw_accesses(self, **kwargs):
        """
        Check whether an public tracker is associated with an embargoed flaw.
        """
        if (
            not self.is_embargoed
            and Flaw.objects.filter(affects__trackers=self, embargoed=True).exists()
        ):
            raise ValidationError(
                "Tracker is public but is associated with an embargoed flaw."
            )

    def _validate_notaffected_open_tracker(self, **kwargs):
        """
        Check whether notaffected products have open trackers.
        """
        affect = self.affects.filter(
            affectedness=Affect.AffectAffectedness.NOTAFFECTED
        ).first()

        if not self.is_closed and affect:
            raise ValidationError(
                f"The tracker is associated with a NOTAFFECTED affect: {affect.uuid}",
            )

    def _validate_ooss_open_tracker(self, **kwargs):
        """
        Check whether out of support scope products have open trackers.
        """
        affect = self.affects.filter(resolution=Affect.AffectResolution.OOSS).first()
        if not self.is_closed and affect:
            raise ValidationError(
                f"The tracker is associated with an OOSS affect: {affect.uuid}",
            )

    def _validate_wontfix_open_tracker(self, **kwargs):
        """
        Check whether wontfix affects have open trackers.
        """
        affect = self.affects.filter(resolution=Affect.AffectResolution.WONTFIX).first()
        if not self.is_closed and affect:
            raise ValidationError(
                f"The tracker is associated with a WONTFIX affect: {affect.uuid}",
            )

    def _validate_multi_flaw_tracker(self, **kwargs):
        """
        validate multi-flaw tracker
        """
        if self.affects.count() < 2:
            return

        first_affect = self.affects.first()
        for affect in self.affects.exclude(uuid=first_affect.uuid):
            if first_affect.ps_module != affect.ps_module:
                raise ValidationError(
                    "Tracker must be associated only with affects with the same PS module"
                )

            if first_affect.ps_component != affect.ps_component:
                raise ValidationError(
                    "Tracker must be associated only with affects with the same PS component"
                )

    def _validate_tracker_bts_match(self, **kwargs):
        """
        validate that the tracker type corresponds to the BTS
        """
        affect = self.affects.first()
        if not affect:
            return

        ps_module = PsModule.objects.filter(name=affect.ps_module).first()
        if not ps_module:
            return

        if self.TYPE2BTS[self.type] != ps_module.bts_name:
            raise ValidationError(
                f"Tracker type and BTS mismatch: {self.type} versus {ps_module.bts_name}"
            )

    def _validate_tracker_duplicate(self, **kwargs):
        """
        validate that there is only one tracker with this update stream associated with each affect
        """
        for affect in self.affects.all():
            if (
                affect.trackers.filter(ps_update_stream=self.ps_update_stream).count()
                > 1
            ):
                raise ValidationError(
                    f"Tracker with the update stream {self.ps_update_stream} "
                    f"is already associated with the affect {affect.uuid}"
                )

    def can_unembargo(self):
        """
        tracker can only be unembargoed when not linked to any embargoed affect
        checking this prevents a premature unembargo of a multi-flaw tracker
        """
        # enforce the reload from DB or
        # we can see an outdated state
        return not self.affects.filter(embargoed=True).exists()

    @property
    def aggregated_impact(self):
        """
        this property simply gives the maximum impact of the related entities
        """
        return max(affect.aggregated_impact for affect in self.affects.all())

    @property
    def bz_id(self):
        """
        shortcut to enable unified Bugzilla Flaw and Tracker handling when meaningful
        """
        # this should be always asserted or we failed
        assert (
            self.type == self.TrackerType.BUGZILLA
        ), "Only Bugzilla trackers have Bugzilla IDs"
        return self.external_system_id or None

    @bz_id.setter
    def bz_id(self, value):
        """
        shortcut to enable unified Bugzilla Flaw and Tracker handling when meaningful
        """
        self.external_system_id = value

    @property
    def fix_state(self):
        """
        Inheritied from SDEngine, see abe12e30a509824629d05e91ce23c5d987e8ad36/sdengine/models.py#L1165
        Trackers can be Bugzilla or Jira Issues. Because Jira Projects can configure anything they want as various statuses and
        resolutions, it's hard to sensibly map tracker status to a finite set of display values.
        We'll do the best we can from data gathered by SDEngine up to 2021-12-14, but these will change in the
        future so review should be performed when revisiting this code.
        """
        if self.status:
            self.status = self.status.lower()
        if self.resolution:
            self.resolution = self.resolution.lower()

        # Eg. GITOPS-1472, AAH-682
        if self.status in ("won't fix", "obsolete"):
            return Affect.AffectFix.WONTFIX
        if self.status in ("done", "resolved", "closed"):
            if self.resolution in ("won't do", "won't fix", "wontfix", "obsolete"):
                return Affect.AffectFix.WONTFIX
            # Added rejected to code inherited from SDEngine because samples such as MGDSTRM-4153
            elif self.resolution in (
                "notabug",
                "not a bug",
                "rejected",
            ):
                return Affect.AffectFix.NOTAFFECTED
            elif self.resolution in ("eol", "out of date"):
                return Affect.AffectFix.OOSS
            elif self.resolution in ("deferred", "nextrelease", "rawhide", "upstream"):
                return Affect.AffectFix.DEFER
        return Affect.AffectFix.AFFECTED

    @property
    def is_closed(self):
        """
        this property unifies the notion of the tracker closure between
        Bugzilla where CLOSED is used and Jira with Closed instead

        note that this reliably covers only the after-OJA world
        while before it is pretty much impossible to unify anything
        """
        return self.status.upper() == "CLOSED"

    @property
    def is_acked(self):
        """
        tracker acked by ProdSec - filed against an acked stream
        the default approach important and critical aggregated impact
        """
        return not self.is_unacked

    @property
    def is_unacked(self):
        """
        tracker not acked by ProdSec - filed against an unacked stream
        the default approach low and moderate aggregated impact
        """
        return (
            PsUpdateStream.objects.filter(
                name=self.ps_update_stream, unacked_to_ps_module__isnull=False
            ).first()
            is not None
        )

    @property
    def is_compliance_priority(self) -> bool:
        """
        Check and return whether this affect module, component and update stream combination is
        compliance priority which is defined in PS constants repo in compliance_priority.yml.

        Compliance priority is always False for LOW impact.
        """
        affect = self.affects.first()
        if not affect:
            return False

        if self.aggregated_impact == Impact.LOW:
            return False

        compliance_priority = CompliancePriority.objects.filter(
            ps_module=affect.ps_module
        ).first()
        if not compliance_priority:
            return False
        if self.ps_update_stream not in compliance_priority.streams:
            return False
        compliance_components = compliance_priority.components
        if not compliance_components:
            # Empty list of components in compliance_components.yml means all components are priority.
            return True
        return affect.ps_component in compliance_components

    @property
    def is_contract_priority(self) -> bool:
        """
        check and return whether this affect module and update stream combination is contract
        priority which is defined in PS constants repo in contract_priority.yml
        """
        return ContractPriority.objects.filter(
            ps_update_stream=self.ps_update_stream
        ).exists()

    download_manager = models.ForeignKey(
        BZTrackerDownloadManager, null=True, blank=True, on_delete=models.CASCADE
    )
    bz_link_manager = models.ForeignKey(
        BZTrackerLinkManager, null=True, blank=True, on_delete=models.CASCADE
    )
    jira_link_manager = models.ForeignKey(
        JiraTrackerLinkManager, null=True, blank=True, on_delete=models.CASCADE
    )


class ErratumManager(TrackingMixinManager):
    """
    erratum manager
    """

    @staticmethod
    def create_erratum(et_id=None, **extra_fields):
        """
        return a new erratum or update an existing erratum without saving
        """
        assert et_id is not None, "Erratum ID must by provided"

        try:
            erratum = Erratum.objects.get(et_id=et_id)
            for attr, value in extra_fields.items():
                setattr(erratum, attr, value)
            return erratum
        except ObjectDoesNotExist:
            return Erratum(et_id=et_id, **extra_fields)


class Erratum(TrackingMixin):
    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    et_id = models.IntegerField(unique=True)  # Five-digit internal ID, e.g. 44547
    advisory_name = models.CharField(max_length=20, unique=True)  # E.g. RHSA-2019:2411

    # creation and last update timestamps are provided by the TrackingMixin
    # and the values are taken from the Errata Tool as the authoritative source
    shipped_dt = models.DateTimeField(null=True, blank=True)

    # An Erratum can fix many trackers, and a tracker can be fixed in multiple errata
    # For example, one erratum may fix a component on RHEL 7
    # And another erratum may fix the same component on RHEL 8
    # But all errata report the same Bugzilla / Jira tracker as "fixed"
    trackers = models.ManyToManyField(Tracker, related_name="errata")

    objects = ErratumManager()

    class Meta:
        verbose_name = "Erratum"
        verbose_name_plural = "Errata"

    def __str__(self):
        # self.advisory_name is already a str, below needed only to fix a warning
        return str(self.advisory_name)


class FlawComment(
    AlertMixin,
    ACLMixin,
    BugzillaSyncMixin,
    TrackingMixin,
):
    """Model representing flaw comments"""

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # external comment id
    external_system_id = models.CharField(max_length=100, blank=True)

    # For bbsync/query.py to mark whether it was sent to BZ
    synced_to_bz = models.BooleanField(default=False)

    # explicitly define comment ordering, from BZ comment 'count'
    order = models.IntegerField(null=True)

    # text of the comment
    text = models.TextField()

    # creator of the comment, which can be passed as an argument when creating it,
    # similar to the flaw's owner field, or if BZ sync is enabled, then it will be
    # implied from the BZ API key owner during sync
    creator = models.CharField(max_length=100, blank=True)

    # whether the comment is internal or not
    is_private = models.BooleanField(default=False)

    # one flaw can have many comments
    flaw = models.ForeignKey(Flaw, on_delete=models.CASCADE, related_name="comments")

    def __str__(self):
        return str(self.uuid)

    class Meta:
        """define meta"""

        ordering = (
            "order",
            "external_system_id",
            "uuid",
            "created_dt",
        )

        indexes = TrackingMixin.Meta.indexes + [
            GinIndex(fields=["acl_read"]),
        ]

        # Ensure that it's not possible to have two bzimports running concurrently
        # and succeed while creating numbering conditions impossible to handle later.
        constraints = [
            models.UniqueConstraint(
                fields=["flaw", "order"], name="unique_per_flaw_comment_nums"
            ),
        ]

    def bzsync(self, *args, bz_api_key=None, **kwargs):
        """
        Bugzilla sync of the FlawComment instance and of the related Flaw instance.
        """

        self.save()

        # Comments need to be synced through flaw
        # If external_system_id is blank, BugzillaSaver posts the new comment
        # and FlawCollector loads the new comment and updates this FlawComment
        # instance to match bugzilla.
        self.flaw.save(*args, bz_api_key=bz_api_key, **kwargs)


class FlawAcknowledgmentManager(ACLMixinManager, TrackingMixinManager):
    """flaw acknowledgment manager"""

    @staticmethod
    def create_flawacknowledgment(flaw, name, affiliation, **extra_fields):
        """return a new flaw acknowledgment or update an existing flaw acknowledgment without saving"""
        try:
            flawacknowledgment = FlawAcknowledgment.objects.get(
                flaw=flaw,
                name=name,
                affiliation=affiliation,
            )
            for attr, value in extra_fields.items():
                setattr(flawacknowledgment, attr, value)
            return flawacknowledgment

        except ObjectDoesNotExist:
            return FlawAcknowledgment(
                flaw=flaw,
                name=name,
                affiliation=affiliation,
                **extra_fields,
            )


class FlawAcknowledgment(AlertMixin, ACLMixin, BugzillaSyncMixin, TrackingMixin):
    """
    Model representing flaw acknowledgments.
    Note that flaws with a public source can't have acknowledgments.
    """

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # The name of the person or entity being acknowledged.
    # max length seen in production as of 02/2023 == 122
    name = models.CharField(max_length=255)

    # The affiliation of the person being acknowledged.
    # max length seen in production as of 02/2023 == 86
    affiliation = models.CharField(max_length=255, blank=True)

    # Whether this acknowledgment comes from an upstream source.
    from_upstream = models.BooleanField()

    # one flaw can have many acknowledgments
    flaw = models.ForeignKey(
        Flaw, on_delete=models.CASCADE, related_name="acknowledgments"
    )

    objects = FlawAcknowledgmentManager()

    class Meta:
        """define meta"""

        unique_together = ["flaw", "name", "affiliation"]
        indexes = TrackingMixin.Meta.indexes + [
            GinIndex(fields=["acl_read"]),
        ]

    def _validate_public_source_no_ack(self, **kwargs):
        """
        Checks that acknowledgments cannot be linked to flaws with public sources.
        """
        if (source := FlawSource(self.flaw.source)) and source.is_public():
            if source.is_private():
                self.alert(
                    "public_source_no_ack",
                    f"Flaw source of type {source} can be public or private, "
                    "ensure that it is private since the Flaw has acknowledgments.",
                    **kwargs,
                )
            else:
                raise ValidationError(
                    f"Flaw contains acknowledgments for public source {self.flaw.source}"
                )

    def bzsync(self, *args, bz_api_key, **kwargs):
        """
        Bugzilla sync of the FlawAcknowledgment instance
        """
        self.save()
        # FlawAcknowledgment needs to be synced through flaw
        self.flaw.save(*args, bz_api_key=bz_api_key, **kwargs)


class FlawReferenceManager(ACLMixinManager, TrackingMixinManager):
    """flawreference manager"""

    @staticmethod
    def create_flawreference(flaw, url, **extra_fields):
        """return a new flawreference or update an existing flawreference without saving"""
        try:
            flawreference = FlawReference.objects.get(flaw=flaw, url=url)
            for attr, value in extra_fields.items():
                setattr(flawreference, attr, value)
            return flawreference

        except ObjectDoesNotExist:
            return FlawReference(flaw=flaw, url=url, **extra_fields)


class FlawReference(AlertMixin, ACLMixin, BugzillaSyncMixin, TrackingMixin):
    """Model representing flaw references"""

    class FlawReferenceType(models.TextChoices):
        """
        Allowable references:

        ARTICLE:
            A link to a Security Bulletin or Knowledge Base Article specifically
            discussing this flaw on the Customer Portal. It always begins with
            "https://accesss.redhat.com/". It must be a Security Bulletin
            for Major Incidents. More general articles like hardening should be
            linked instead in EXTERNAL.

        EXTERNAL:
            URL links to other trustworthy sources of information about this
            vulnerability. A link should not point to a missing resource.
            Since these links are displayed on the CVE page of the flaw, we only
            want to include respectable sources (such as upstream advisories,
            analysis of security researches, etc.).

        SOURCE:
            A link from which we obtained information about a flaw.
            This should be used mostly when converting Snippet to Flaw.
        """

        # NOTE: when moving or renaming this enum, please check and modify
        # config/settings.py::SPECTACULAR_SETTINGS::ENUM_NAME_OVERRIDES accordingly

        ARTICLE = "ARTICLE"
        EXTERNAL = "EXTERNAL"
        SOURCE = "SOURCE"

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    type = models.CharField(
        choices=FlawReferenceType.choices,
        default=FlawReferenceType.EXTERNAL,
        max_length=50,
    )

    url = models.URLField(max_length=2048)

    description = models.TextField(blank=True)

    # one flaw can have many references
    flaw = models.ForeignKey(Flaw, on_delete=models.CASCADE, related_name="references")

    objects = FlawReferenceManager()

    class Meta:
        """define meta"""

        unique_together = ["flaw", "url"]

        indexes = TrackingMixin.Meta.indexes + [
            GinIndex(fields=["acl_read"]),
        ]

    def _validate_article_link(self, **kwargs):
        """
        Checks that an article link begins with https://access.redhat.com/.
        """
        if self.type == self.FlawReferenceType.ARTICLE and not self.url.startswith(
            "https://access.redhat.com/"
        ):
            raise ValidationError(
                r"A flaw reference of the ARTICLE type does not begin with "
                r"https://access.redhat.com/."
            )

    def _validate_article_links_count_via_flawreferences(self, **kwargs):
        """
        Checks that a flaw has maximally one article link.
        """
        old_reference = FlawReference.objects.filter(uuid=self.uuid).first()
        article_count = 0
        if self.type == FlawReference.FlawReferenceType.ARTICLE:
            if (
                not old_reference
                or old_reference.type != FlawReference.FlawReferenceType.ARTICLE
            ):
                article_count = 1

        article_links = self.flaw.references.filter(
            type=FlawReference.FlawReferenceType.ARTICLE
        )
        article_count += article_links.count()

        if article_count > 1:
            raise ValidationError(
                f"A flaw has {article_count} article links, but only 1 is allowed."
            )

    def bzsync(self, *args, bz_api_key, **kwargs):
        """
        Bugzilla sync of the FlawReference instance
        """
        self.save()
        # FlawReference needs to be synced through flaw
        self.flaw.save(*args, bz_api_key=bz_api_key, **kwargs)


class VersionStatus(models.TextChoices):
    AFFECTED = "AFFECTED"
    UNAFFECTED = "UNAFFECTED"
    UNKNOWN = "UNKNOWN"


class Version(PolymorphicModel):
    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        """define meta"""

        verbose_name = "Old Version"

    def validate(self, *args, **kwargs):
        """validate versionRange model"""
        super().clean_fields(*args, **kwargs)


# See CVE v5 reporting schema
# https://gist.github.com/rsc/0b448f99e73bf745eeca1319d882efb2#versions-and-version-ranges
class CVEv5Version(Version):
    """
    Model representing a package version

    This model is deprecated. Use PackageVer instead. Delete when it's clear
    that PackageVer works correctly.
    """

    # TODO add type and comparison fields
    # We didn't add it yet because exisiting BZ data is not accurate
    # enough to determine type (eg. semver, rpm) consistently
    # should should be based on collection_url or entered manually

    version = models.CharField(max_length=1024)

    status = models.CharField(choices=VersionStatus.choices, max_length=20)


class PackageVersions(PolymorphicModel):
    """
    This model is deprecated. Use Package instead. Delete when it's clear
    that Package works correctly.
    """

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    flaw = models.ForeignKey(
        Flaw,
        related_name="old_package_versions",
        on_delete=models.CASCADE,
    )

    versions = models.ManyToManyField(Version)

    class Meta:
        """define meta"""

        verbose_name = "Old Package Versions"

    def validate(self, *args, **kwargs):
        """validate package versions model"""
        super().clean_fields(*args, **kwargs)


class CVEv5PackageVersions(PackageVersions):
    """
    This model is deprecated. Use Package instead. Delete when it's clear
    that Package works correctly.
    """

    # the name of the affected upstream package within collection_url
    # will be reported to Mitre as packageName
    # see https://gist.github.com/rsc/0b448f99e73bf745eeca1319d882efb2#product-objects
    package = models.CharField(max_length=2058)

    default_status = models.CharField(
        choices=VersionStatus.choices, max_length=1024, default=VersionStatus.UNAFFECTED
    )

    def validate(self, *args, **kwargs):
        """validate package versions model"""
        super().clean_fields(*args, **kwargs)


class PackageManager(ACLMixinManager, TrackingMixinManager):
    @staticmethod
    def create_package(flaw, package, **extra_fields):
        """
        Return a new Package, or update an existing Package without saving.
        Unlike other similar manager methods in this file, new Package
        instance is saved into database to allow relationships with PackageVer.
        """
        try:
            package = Package.objects.get(flaw=flaw, package=package)
            for attr, value in extra_fields.items():
                setattr(package, attr, value)
        except ObjectDoesNotExist:
            package = Package(flaw=flaw, package=package, **extra_fields)
            package.save()
        return package


class Package(AlertMixin, ACLMixin, BugzillaSyncMixin, TrackingMixin):
    """
    Model representing a package with connected versions.

    The model's structure allows future extensibility with features from the CVE 5.0 schema.
    Currently, it tracks only versions corresponding to bugzilla fixed_in field, which correspond to
    CVE 5.0's `"status": "unaffected"`.
    References:
    - https://github.com/CVEProject/cve-schema/blob/master/schema/v5.0/docs/versions.md
    - https://github.com/CVEProject/cve-schema/blob/master/schema/v5.0/CVE_JSON_5.0_schema.json
    """

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    flaw = models.ForeignKey(
        Flaw,
        related_name="package_versions",
        on_delete=models.CASCADE,
    )

    package = models.CharField(max_length=2048)

    objects = PackageManager()

    def bzsync(self, *args, bz_api_key, **kwargs):
        """
        Bugzilla sync of the Package instance and linked PackageVer instances.
        """
        self.save()
        # needs to be synced through flaw
        self.flaw.save(*args, bz_api_key=bz_api_key, **kwargs)

    class Meta:
        """define meta"""

        indexes = TrackingMixin.Meta.indexes + [
            GinIndex(fields=["acl_read"]),
        ]


class PackageVer(models.Model):
    """Model representing a package version"""

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    package = models.ForeignKey(
        Package,
        related_name="versions",
        on_delete=models.CASCADE,
    )

    class Meta:
        verbose_name = "Version"

    version = models.CharField(max_length=1024)


class PsProduct(models.Model):

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # short name of the product, also known as product id from SFM2
    short_name = models.CharField(max_length=50, unique=True)

    # name of the product
    name = models.CharField(max_length=100)

    # team responsible for the product
    team = models.CharField(max_length=50)

    # the business unit to which the product belongs
    business_unit = models.CharField(max_length=50)

    @property
    def is_community(self):
        """
        is community boolean property
        """
        return self.business_unit == "Community"


class PsModule(NullStrFieldsMixin, ValidateMixin):

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # name of the module
    name = models.CharField(max_length=100, unique=True)

    public_description = models.TextField()
    cpe = fields.ArrayField(models.TextField(), default=list, blank=True)

    # Flags
    private_trackers_allowed = models.BooleanField(default=False)
    autofile_trackers = models.BooleanField(default=False)
    special_handling_features = fields.ArrayField(
        models.TextField(), default=list, blank=True
    )

    # BTS
    bts_name = models.CharField(max_length=50)
    bts_key = models.CharField(max_length=100)
    bts_groups = models.JSONField(default=dict)

    # Lifecycle
    supported_from_dt = models.DateTimeField(null=True, blank=True)
    supported_until_dt = models.DateTimeField(null=True, blank=True)

    # CC Lists
    default_cc = fields.ArrayField(
        models.CharField(max_length=50), default=list, blank=True
    )
    component_cc = models.JSONField(default=dict, blank=True)
    private_tracker_cc = fields.ArrayField(
        models.CharField(max_length=50), default=list, blank=True
    )

    # Component overrides
    default_component = models.CharField(max_length=100, blank=True)
    component_overrides = models.JSONField(default=dict, blank=True)

    # Update Streams
    # implicit:
    # ps_update_streams
    # active_ps_update_streams
    # default_ps_update_streams
    # aus_ps_update_streams
    # unacked_ps_update_stream

    ps_product = models.ForeignKey(
        PsProduct, on_delete=models.CASCADE, related_name="ps_modules"
    )

    @property
    def is_rhscl(self) -> bool:
        """
        check and return whether the PS module is RHSCL one

        Red Hat Software Collections represent an extra layer in
        the component hierarchy and may require special handling
        """
        return self.bts_key == RHSCL_BTS_KEY

    @property
    def y_streams(self):
        """Current Y-stream(s) - it can be more of them"""

        return list(self.active_ps_update_streams.exclude(name__endswith="z"))

    @property
    def z_stream(self):
        """Current Z-stream"""
        z_streams = self.active_ps_update_streams.filter(name__endswith="z")
        return (
            max(list(z_streams), key=ps_update_stream_natural_keys)
            if z_streams
            else None
        )

    def subcomponent(self, component) -> Union[str, None]:
        """
        return the subcomponent for the given component or None if not present
        """
        if (
            self.component_overrides
            and component in self.component_overrides
            and isinstance(self.component_overrides[component], dict)
            and self.component_overrides[component].get("sub_component")
        ):
            return self.component_overrides[component]["sub_component"]


class PsUpdateStream(NullStrFieldsMixin, ValidateMixin):

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    name = models.CharField(max_length=100, unique=True)
    version = models.CharField(max_length=50, blank=True)
    target_release = models.CharField(max_length=50, blank=True)
    rhsa_sla_applicable = models.BooleanField(default=True)

    additional_fields = models.JSONField(default=dict, blank=True)
    collections = fields.ArrayField(models.TextField(), default=list, blank=True)
    flags = fields.ArrayField(models.TextField(), default=list, blank=True)

    # related PS Module
    ps_module = models.ForeignKey(
        PsModule,
        on_delete=models.SET_NULL,
        related_name="ps_update_streams",
        null=True,
        blank=True,
    )

    # special PS Module relations
    active_to_ps_module = models.ForeignKey(
        PsModule,
        on_delete=models.SET_NULL,
        related_name="active_ps_update_streams",
        null=True,
        blank=True,
    )
    default_to_ps_module = models.ForeignKey(
        PsModule,
        on_delete=models.SET_NULL,
        related_name="default_ps_update_streams",
        null=True,
        blank=True,
    )
    aus_to_ps_module = models.ForeignKey(
        PsModule,
        on_delete=models.SET_NULL,
        related_name="aus_ps_update_streams",
        null=True,
        blank=True,
    )
    eus_to_ps_module = models.ForeignKey(
        PsModule,
        on_delete=models.SET_NULL,
        related_name="eus_ps_update_streams",
        null=True,
        blank=True,
    )
    # there is only one unacked PS update stream
    # but let us link it the same way so it is unified
    unacked_to_ps_module = models.ForeignKey(
        PsModule,
        on_delete=models.SET_NULL,
        related_name="unacked_ps_update_stream",
        null=True,
        blank=True,
    )


class PsContact(NullStrFieldsMixin, ValidateMixin):

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # base RedHat username, also known as id in SFM2
    username = models.CharField(max_length=100, unique=True)

    # BTS usernames
    bz_username = models.CharField(max_length=100, blank=True)
    jboss_username = models.CharField(max_length=100, blank=True)


class Profile(models.Model):
    user = models.OneToOneField(
        User,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    bz_user_id = models.CharField(max_length=100, blank=True)
    jira_user_id = models.CharField(max_length=100, blank=True)

    @property
    def username(self):
        return self.user.username

    def __str__(self):
        return self.username


class CompliancePriority(models.Model):
    """
    One instance of this model represents one
    model in PS constant compliance priority list.
    """

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    ps_module = models.CharField(max_length=100)
    streams = models.JSONField(default=list)
    components = models.JSONField(default=list)


class ContractPriority(models.Model):
    """
    an instance of this model represents one
    entry in PS constant contract priority list
    """

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    ps_update_stream = models.CharField(max_length=100)


class UbiPackage(models.Model):
    """
    An instance of this model represents one
    entry in ubi packages list from PS_Constant project
    """

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # PsComponent name
    name = models.CharField(max_length=255)

    # major stream name (e.g. 'rhel-9') - Relates to PsUpdateStream any starting with this string (e.g. ['rhel-9', 'rhel-9.0', 'rhel-9.0.0.z])
    major_stream_version = models.CharField(max_length=100)


class SpecialConsiderationPackage(models.Model):
    """
    An instance of this model represents one
    entry in special consideration packages list
    from PS_Constant project
    """

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # PsComponent name
    name = models.CharField(max_length=255, unique=True)


from apps.bbsync.cc import AffectCCBuilder, RHSCLAffectCCBuilder  # noqa: E402

from .constants import (  # noqa: E402
    AFFECTEDNESS_HISTORICAL_VALID_RESOLUTIONS,
    AFFECTEDNESS_VALID_RESOLUTIONS,
    BZ_ID_SENTINEL,
    COMPONENTS_WITHOUT_COLLECTION,
    CVSS3_SEVERITY_SCALE,
    OSIDB_API_VERSION,
    SERVICES_PRODUCTS,
)
