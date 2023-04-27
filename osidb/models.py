"""
draft model for end to end testing
"""
import json
import logging
import re
import uuid
from decimal import Decimal
from typing import Union

from django.contrib.auth.models import User
from django.contrib.postgres import fields
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_deprecate_fields import deprecate_field
from polymorphic.models import PolymorphicModel
from psqlextra.fields import HStoreField

from apps.bbsync.constants import RHSCL_BTS_KEY
from apps.bbsync.mixins import BugzillaSyncMixin
from apps.bbsync.models import BugzillaComponent
from apps.exploits.mixins import AffectExploitExtensionMixin
from apps.exploits.query_sets import AffectQuerySetExploitExtension
from apps.osim.workflow import WorkflowModel
from collectors.bzimport.constants import FLAW_PLACEHOLDER_KEYWORD

from .mixins import (
    ACLMixin,
    ACLMixinManager,
    AlertMixin,
    NullStrFieldsMixin,
    TrackingMixin,
    TrackingMixinManager,
    ValidateMixin,
)
from .validators import (
    no_future_date,
    validate_cve_id,
    validate_cvss2,
    validate_cvss3,
    validate_cwe_id,
)

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
            + SearchVector("description", weight="B")
            + SearchVector("summary", weight="C")
            + SearchVector("statement", weight="D")
        )

    rank = SearchRank(vector, query, cover_density=True)
    # Consider proximity of matching terms when ranking

    return queryset.annotate(rank=rank).filter(rank__gt=0).order_by("-rank")
    # Add "rank" column to queryset based on search result relevance
    # Exclude results that don't match (rank 0)
    # Order remaining results from highest rank to lowest


class FlawHistoryManager(ACLMixinManager):
    """flaw history manager"""

    @staticmethod
    def fts_search(q):
        """full text search using postgres FTS via django.contrib.postgres"""
        return search_helper(FlawHistory.objects.get_queryset(), (), q)
        # Search default Flaw fields (title, description, summary, statement) with default weights
        # If search has no results, this will now return an empty queryset


class FlawType(models.TextChoices):
    """allowable types"""

    VULNERABILITY = "VULNERABILITY"
    WEAKNESS = "WEAKNESS"


class FlawImpact(models.TextChoices):
    """allowable impact"""

    NOVALUE = ""
    LOW = "LOW"
    MODERATE = "MODERATE"
    IMPORTANT = "IMPORTANT"
    CRITICAL = "CRITICAL"


class FlawResolution(models.TextChoices):
    """allowable resolution"""

    NOVALUE = ""
    DUPLICATE = "DUPLICATE"
    WONTFIX = "WONTFIX"
    NOTABUG = "NOTABUG"
    ERRATA = "ERRATA"
    CANTFIX = "CANTFIX"
    DEFERRED = "DEFERRED"
    CURRENTRELEASE = "CURRENTRELEASE"
    UPSTREAM = "UPSTREAM"
    RAWHIDE = "RAWHIDE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    NEXTRELEASE = "NEXTRELEASE"
    WORKSFORME = "WORKSFORME"
    EOL = "EOL"


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
    OCERT = "OCERT"
    OPENOFFICE = "OPENOFFICE"  # OPENOFFICE.ORG
    OPENSSL = "OPENSSL"
    OPENSUSE = "OPENSUSE"
    ORACLE = "ORACLE"
    OSS = "OSS"
    OSS_SECURITY = "OSSSECURITY"
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

    def is_private(self):
        """
        Returns True if the source is private, False otherwise.

        Note that the following sources can be both public and private:
        DEBIAN, MAGEIA, GENTOO, SUSE, UBUNTU
        """
        return self in {
            # PRIVATE_SOURCES from SFM2
            self.ADOBE,
            self.APPLE,
            self.CERT,
            self.CUSTOMER,
            self.DEBIAN,
            self.DISTROS,
            self.GENTOO,
            self.GOOGLE,
            self.HW_VENDOR,
            self.MAGEIA,
            self.MOZILLA,
            self.OPENSSL,
            self.REDHAT,
            self.RESEARCHER,
            self.SECUNIA,
            self.UPSTREAM,
            self.XEN,
            self.VENDOR_SEC,
            self.SUN,
            self.SUSE,
            self.UBUNTU,
        }

    def is_public(self):
        """
        Returns True if the source is public, False otherwise.

        Note that the following sources can be both public and private:
        DEBIAN, MAGEIA, GENTOO, SUSE, UBUNTU
        """
        return not self.is_private() or self in {
            self.DEBIAN,
            self.MAGEIA,
            self.GENTOO,
            self.SUSE,
            self.UBUNTU,
        }

    def is_allowed(self):
        """
        Returns True if the source is allowed (not historical), False otherwise.
        """
        return self in [
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
        ]


class FlawHistory(NullStrFieldsMixin, ValidateMixin, ACLMixin):
    """match existing history table for flaws"""

    pgh_created_at = models.DateTimeField(null=True)
    # this model is unused so we don't care that it's a CharField with null=True
    pgh_label = models.CharField(max_length=100, null=True)  # noqa: DJ01

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # CVE-ID, should be unique, from BZ alias
    cve_id = models.CharField(max_length=500, blank=True)

    # vulnerability or weakness
    type = models.CharField(
        choices=FlawType.choices, default=FlawType.VULNERABILITY, max_length=20
    )

    # flaw severity, from srtnotes "impact"
    impact = models.CharField(choices=FlawImpact.choices, max_length=20, blank=True)

    # from BZ summary
    title = models.TextField()

    # from BZ description
    description = models.TextField()

    # from doc_team summary
    summary = models.TextField(blank=True)

    # if redhat cve-id then this is required, from srtnotes "statement"
    # eventually should compose up from affects
    statement = models.TextField(blank=True)

    # contains a single cwe-id or cwe relationships, from srtnotes "cwe"
    cwe_id = models.CharField(blank=True, max_length=50, validators=[validate_cwe_id])

    # date when embargo is to be lifted, from srtnotes "public"
    unembargo_dt = models.DateTimeField(null=True, blank=True)

    # reported source of flaw, from impactsrtnotes "source"
    source = models.CharField(choices=FlawSource.choices, max_length=500, blank=True)

    # reported date, from srtnotes "reported"
    reported_dt = models.DateTimeField(
        null=True, blank=True, validators=[no_future_date]
    )

    # , from srtnotes "cvss2"
    cvss2 = models.CharField(max_length=100, blank=True, validators=[validate_cvss2])
    cvss2_score = models.FloatField(null=True, blank=True)

    # , from srtnotes "cvss3"
    cvss3 = models.CharField(max_length=100, blank=True, validators=[validate_cvss3])
    cvss3_score = models.FloatField(null=True, blank=True)

    # should be set True if MAJOR_INCIDENT or MAJOR_INCIDENT_LITE FlawMeta exists, from BZ flagsq
    is_major_incident = models.BooleanField(default=False)

    # TBD-  affects history
    # TBD-  meta history

    # non operational meta data
    meta_attr = HStoreField(default=dict)

    class Meta:
        """define meta"""

        verbose_name = "FlawHistory"

    def __str__(self):
        """convert to string"""
        return str(self.uuid)

    objects = FlawHistoryManager()


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
        # Search default Flaw fields (title, description, summary, statement) with default weights
        # If search has no results, this will now return an empty queryset


class Flaw(
    ACLMixin,
    BugzillaSyncMixin,
    NullStrFieldsMixin,
    TrackingMixin,
    WorkflowModel,
):
    """Model flaw"""

    class FlawState(models.TextChoices):
        """allowable Bugzilla states"""

        ASSIGNED = "ASSIGNED"
        CLOSED = "CLOSED"
        MODIFIED = "MODIFIED"
        NEW = "NEW"
        ON_DEV = "ON_DEV"
        ON_QA = "ON_QA"
        POST = "POST"
        RELEASE_PENDING = "RELEASE_PENDING"
        VERIFIED = "VERIFIED"

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

    # vulnerability or weakness
    type = models.CharField(
        choices=FlawType.choices, default=FlawType.VULNERABILITY, max_length=20
    )

    # flaw state, from BZ status
    state = deprecate_field(
        models.CharField(
            choices=FlawState.choices, default=FlawState.NEW, max_length=100
        ),
        # required to keep backwards compatibility
        return_instead=FlawState.NEW,
    )

    # resolution
    resolution = deprecate_field(
        models.CharField(
            choices=FlawResolution.choices,
            default=FlawResolution.NOVALUE,
            max_length=100,
            blank=True,
        ),
        # required to keep backwards compatibility
        return_instead=FlawResolution.NOVALUE,
    )

    # flaw severity, from srtnotes "impact"
    impact = models.CharField(choices=FlawImpact.choices, max_length=20, blank=True)

    # flaw component was originally a part of the Bugzilla sumary
    # so the value may depend on how successfully it was parsed
    component = models.CharField(max_length=100, blank=True)

    # from BZ summary
    title = models.TextField()

    # from BZ description
    description = models.TextField()

    # from doc_team summary
    summary = models.TextField(blank=True)

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

    # , from srtnotes "cvss2"
    cvss2 = models.CharField(max_length=100, blank=True, validators=[validate_cvss2])
    cvss2_score = models.FloatField(null=True, blank=True)

    # , from srtnotes "cvss3"
    cvss3 = models.CharField(max_length=100, blank=True, validators=[validate_cvss3])
    cvss3_score = models.FloatField(null=True, blank=True)

    # updated from Dashboard's /rest/api/latest/nvd_cvss
    nvd_cvss2 = models.CharField(
        max_length=100, blank=True, validators=[validate_cvss2]
    )
    nvd_cvss3 = models.CharField(
        max_length=100, blank=True, validators=[validate_cvss3]
    )

    # should be set True if MAJOR_INCIDENT or MAJOR_INCIDENT_LITE FlawMeta exists, from BZ flagsq
    is_major_incident = models.BooleanField(default=False)

    # non operational meta data
    meta_attr = HStoreField(default=dict)

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
        ]

    def __str__(self):
        """convert to string"""
        return str(self.uuid)

    def _validate_rh_nvd_cvss_score_diff(self):
        """
        Checks that the difference between the RH and NVD CVSS score is not >= 1.0
        """
        if self.cvss3_score is None or not self.nvd_cvss3:
            return
        # we don't store the nvd_cvss3_score directly unlike the RH one
        nvd_cvss3_score = Decimal(self.nvd_cvss3.split("/", 1)[0])
        rh_cvss3_score = Decimal(str(self.cvss3_score))

        if abs(nvd_cvss3_score - rh_cvss3_score) >= Decimal("1.0"):
            self.alert(
                "rh_nvd_cvss_score_diff",
                f"RH and NVD CVSSv3 score differs by 1.0 or more - "
                f"RH {rh_cvss3_score} | NVD {nvd_cvss3_score}",
            )

    def _validate_rh_nvd_cvss_severity_diff(self):
        """
        Checks that NVD and RH CVSS are not of a different severity.
        """
        if self.cvss3_score is None or not self.nvd_cvss3:
            return
        nvd_cvss3_score = Decimal(self.nvd_cvss3.split("/", 1)[0])
        rh_cvss3_score = Decimal(str(self.cvss3_score))

        rh_severity = nvd_severity = None
        for key, value in CVSS3_SEVERITY_SCALE.items():
            lower, upper = value

            if lower <= rh_cvss3_score <= upper:
                rh_severity = key

            if lower <= nvd_cvss3_score <= upper:
                nvd_severity = key

        if rh_severity != nvd_severity:
            self.alert(
                "rh_nvd_cvss_severity_diff",
                "RH and NVD CVSSv3 score difference crosses severity boundary - "
                f"RH {rh_cvss3_score}:{rh_severity} | "
                f"NVD {nvd_cvss3_score}:{nvd_severity}",
            )

    def _validate_nonempty_source(self):
        """
        checks that the source is not empty

        we cannot enforce this by model definition
        as the old flaws may have no source
        """
        if not self.source:
            raise ValidationError("Source value is required.")

    def _validate_embargoed_source(self):
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
                )
            else:
                raise ValidationError(
                    f"Flaw is embargoed but contains public source: {self.source}"
                )

    def _validate_reported_date(self):
        """
        Checks that the flaw has non-empty reported_dt
        """
        if self.reported_dt is None:
            raise ValidationError("Flaw has an empty reported_dt")

    def _validate_public_unembargo_date(self):
        """
        Check that an unembargo date (public date) exists and is in the past if the Flaw is public
        """
        if not self.is_embargoed:
            if self.unembargo_dt is None:
                raise ValidationError("Public flaw has an empty unembargo_dt")
            if self.unembargo_dt > timezone.now():
                raise ValidationError("Public flaw has a future unembargo_dt")

    def _validate_future_unembargo_date(self):
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

    def _validate_cvss3(self):
        """
        Check that a CVSSv3 string is present.
        """
        if not self.cvss3:
            raise ValidationError("CVSSv3 score is missing")

    def _validate_summary_major_incident(self):
        """
        Check that a flaw that is a major incident has a summary
        """
        req = self.meta.filter(type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY).last()
        if not self.is_major_incident or (req and req.meta_attr.get("status") == "-"):
            return

        if not self.summary:
            raise ValidationError("Flaw marked as Major Incident does not have Summary")

        if not req or req.meta_attr.get("status") == "?":
            raise ValidationError(
                "Flaw marked as Major Incident does not have Summary reviewed"
            )

        # XXX: In SFM2 we check that the REQUIRES_DOC_TEXT flag is set by
        # someone who has review access rights, it is uncertain whether
        # we'd need this in OSIDB as ideally we would block non-authorized
        # users from reviewing in the first place, in which case we don't
        # need to perform this validation

    def _validate_embargoing_public_flaw(self):
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

    def _validate_cwe_format(self):
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

    def _validate_flaw_without_affect(self):
        """
        Check if flaw have at least one affect
        """
        # Skip validation at creation allowing to draft a Flaw
        if self._state.adding:
            return

        if not Affect.objects.filter(flaw=self).exists():
            raise ValidationError("Flaw does not contain any affects.")

    def _validate_nonempty_impact(self):
        """
        check that the impact is not empty

        we cannot enforce this by model definition
        as the old flaws may have no impact
        """
        if not self.impact:
            raise ValidationError("Impact value is required.")

    def _validate_nonempty_component(self):
        """
        check that the component is not empty

        we cannot enforce this by model definition
        as the old flaws may have no component
        """
        if not self.component:
            raise ValidationError("Component value is required.")

    def _validate_unsupported_impact_change(self):
        """
        Check that an update of a flaw with open trackers does not change between
        Critical/Important/Major Incident and Moderate/Low and vice-versa.
        """
        if self._state.adding:
            return

        old_flaw = Flaw.objects.get(pk=self.pk)
        was_high_impact = (
            old_flaw.impact in [FlawImpact.CRITICAL, FlawImpact.IMPORTANT]
            or old_flaw.is_major_incident
        )
        is_high_impact = (
            self.impact in [FlawImpact.CRITICAL, FlawImpact.IMPORTANT]
            or self.is_major_incident
        )
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
            )

    def _validate_no_placeholder(self):
        """
        restrict any write operations on placeholder flaws

        they have a special handling mainly in sense
        of visibility and we deprecate this concept
        """
        if self.is_placeholder:
            raise ValidationError(
                "OSIDB does not support write operations on placeholder flaws"
            )

    def _validate_special_handling_modules(self):
        """
        Alerts in case flaw affects a special handling module
        but miss summary or statement
        """
        if self.statement and self.summary:
            return

        affected_modules = self.affects.values_list("ps_module")
        special_modules = PsModule.objects.filter(
            special_handling_features__isnull=False, name__in=affected_modules
        )
        if special_modules.exists():
            if not self.summary:
                self.alert(
                    "special_handling_flaw_missing_summary",
                    f"Affected modules ({','.join(special_modules.values_list('name', flat=True))}) "
                    "are marked as special handling but flaw does not contain summary.",
                )
            if not self.statement:
                self.alert(
                    "special_handling_flaw_missing_statement",
                    f"Affected modules ({','.join(special_modules.values_list('name', flat=True))}) "
                    "are marked as special handling but flaw does not contain statement.",
                )

    def _validate_private_source_no_ack(self):
        """
        Checks that flaws with private sources have ACK.
        """
        if (source := FlawSource(self.source)) and source.is_private():
            if self.meta.filter(type=FlawMeta.FlawMetaType.ACKNOWLEDGMENT).exists():
                return

            if source.is_public():
                alert_text = (
                    f"Flaw source of type {source} can be public or private, "
                    "ensure that it is public since the Flaw has no acknowledgments."
                )
            else:
                alert_text = (
                    f"Flaw has no acknoledgments but source of type {source} is private, "
                    "include them in acknowledgments."
                )
            self.alert(
                "private_source_no_ack",
                alert_text,
            )

    def _validate_allowed_source(self):
        """
        Checks that the flaw source is allowed (not historical).
        """
        if self.source and not FlawSource(self.source).is_allowed():
            raise ValidationError("The flaw has a disallowed (historical) source.")

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
        return self.meta_attr.get("bz_id", None)

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
        """check that all affects with FIX resolution have associated trackers filed"""
        return all(
            affect.trackers.exists()
            for affect in self.affects.filter(resolution=Affect.AffectResolution.FIX)
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
        # imports here to prevent cycles
        from apps.bbsync.save import BugzillaSaver
        from collectors.bzimport.collectors import FlawCollector

        # sync to Bugzilla
        bs = BugzillaSaver(self, bz_api_key)
        self = bs.save()
        # save in case a new Bugzilla ID was obtained
        # so the flaw is later matched in BZ import
        # and do not care for validations here
        kwargs["raise_validation_error"] = False
        self.save(*args, **kwargs)
        # fetch from Bugzilla
        fc = FlawCollector()
        fc.sync_flaw(self.bz_id)


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


class Affect(
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

    class AffectImpact(models.TextChoices):
        """allowable impact"""

        NOVALUE = ""
        LOW = "LOW"
        MODERATE = "MODERATE"
        IMPORTANT = "IMPORTANT"
        CRITICAL = "CRITICAL"

    class AffectFix(models.TextChoices):
        AFFECTED = "AFFECTED"
        NOTAFFECTED = "NOTAFFECTED"
        WONTFIX = "WONTFIX"
        OOSS = "OOSS"
        DEFER = "DEFER"

    class AffectType(models.TextChoices):
        """allowable type"""

        DEFAULT = "DEFAULT"  # we may have different types of affects in the future

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # type
    type = models.CharField(
        choices=AffectType.choices, max_length=10, default=AffectType.DEFAULT
    )

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
    impact = models.CharField(choices=AffectImpact.choices, max_length=20, blank=True)

    # from srtnotes affects/cvss2
    cvss2 = models.CharField(max_length=100, blank=True, validators=[validate_cvss2])
    cvss2_score = models.FloatField(null=True, blank=True)

    # from srtnotes affects/cvss3
    cvss3 = models.CharField(max_length=100, blank=True, validators=[validate_cvss3])
    cvss3_score = models.FloatField(null=True, blank=True)

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
        ]

    # objects = AffectManager()
    objects = AffectManager.from_queryset(AffectQuerySetExploitExtension)()

    def __str__(self):
        return str(self.uuid)

    def _validate_ps_module_old_flaw(self):
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
                )

    def _validate_ps_module_new_flaw(self):
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

    def _validate_sofware_collection(self):
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
            )

        if not is_valid_component:
            self.alert(
                "flaw_affects_rhscl_invalid_collection",
                f"PSComponent {self.ps_component} for {self.ps_module} "
                "does not match any valid collection",
            )

    def _validate_exceptional_affectedness_resolution(self):
        """
        Alerts that an old flaw have empty affectedness.
        (Only accepts WONTFIX and DEFER as resolution, validated by other validation)
        """
        valid_resolutions = [
            Affect.AffectResolution.WONTFIX,
            Affect.AffectResolution.DEFER,
        ]
        if (
            self.affectedness == Affect.AffectAffectedness.NOVALUE
            and self.resolution in valid_resolutions
        ):
            self.alert(
                "flaw_exceptional_affect_status",
                f"Affect ({self.uuid}) for {self.ps_module}/{self.ps_component} is in "
                "a exceptional state having no affectedness.",
            )

    def _validate_affect_status_resolution(self):
        """
        Validates that affected product have a valid combination of affectedness and resolution
        """
        if self.resolution not in AFFECTEDNESS_VALID_RESOLUTIONS[self.affectedness]:
            raise ValidationError(
                f"{self.resolution} is not a valid resolution for {self.affectedness}."
            )

    def _validate_notaffected_open_tracker(self):
        """
        Check whether notaffected products have open trackers.
        """
        if (
            self.affectedness == Affect.AffectAffectedness.NOTAFFECTED
            and self.trackers.exclude(status__iexact="CLOSED").exists()
        ):
            raise ValidationError(
                f"Affect ({self.uuid}) for {self.ps_module}/{self.ps_component} is marked as "
                "NOTAFFECTED but has open tracker(s).",
            )

    def _validate_wontfix_open_tracker(self):
        """
        Check whether wontfix affects have open trackers.
        """
        if (
            self.resolution == Affect.AffectResolution.WONTFIX
            and self.trackers.exclude(status__iexact="CLOSED").exists()
        ):
            raise ValidationError(
                f"Affect ({self.uuid}) for {self.ps_module}/{self.ps_component} is marked as "
                "WONTFIX but has open tracker(s).",
            )

    def _validate_unknown_component(self):
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
                'Component "{}" for {} did not match BTS component (in {}) '
                "nor component from Product Definitions"
            )
            alert_text = alert_text.format(
                component, self.ps_module, ps_module.bts_name
            )
            self.alert(
                "flaw_affects_unknown_component",
                alert_text,
            )

    def _validate_wontreport_products(self):
        """
        Validate that affected/wontreport only can be used for
        products associated with services
        """
        if self.resolution == Affect.AffectResolution.WONTREPORT:
            ps_module = PsModule.objects.filter(name=self.ps_module).first()
            if (
                not ps_module
                or ps_module.ps_product.short_name not in SERVICES_PRODUCTS
            ):
                raise ValidationError(
                    "wontreport can only be associated with service products"
                )

    def _validate_wontreport_severity(self):
        """
        Validate that wontreport only can be used for
        low or moderate severity flaws
        """
        if (
            self.resolution == Affect.AffectResolution.WONTREPORT
            and self.impact
            not in [Affect.AffectImpact.LOW, Affect.AffectImpact.MODERATE]
        ):
            raise ValidationError(
                "wontreport can only be associated with low or moderate severity"
            )

    def _validate_special_handling_modules(self):
        """
        Alerts in case flaw affects a special handling module
        but miss summary or statement
        """
        if not self.flaw or self.flaw.statement and self.flaw.summary:
            return

        special_module = PsModule.objects.filter(
            special_handling_features__isnull=False, name=self.ps_module
        )
        if special_module.exists():
            if not self.flaw.summary:
                self.flaw.alert(
                    "special_handling_flaw_missing_summary",
                    f"Affected module ({special_module.first().name}) "
                    "are marked as special handling but flaw does not contain summary.",
                )
            if not self.flaw.statement:
                self.flaw.alert(
                    "special_handling_flaw_missing_statement",
                    f"Affected module ({special_module.first().name}) "
                    "are marked as special handling but flaw does not contain statement.",
                )

    @property
    def delegated_resolution(self):
        """affect delegated resolution based on resolutions of related trackers"""
        if not (
            self.affectedness == Affect.AffectAffectedness.AFFECTED
            and self.resolution == Affect.AffectResolution.DELEGATED
        ):
            return None

        trackers = self.trackers.all()
        if not trackers:
            return Affect.AffectFix.AFFECTED

        statuses = [tracker.fix_state for tracker in trackers]
        for status in (
            Affect.AffectFix.NOTAFFECTED,
            Affect.AffectFix.AFFECTED,
            Affect.AffectFix.WONTFIX,
            Affect.AffectFix.OOSS,
            Affect.AffectFix.DEFER,
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

    def bzsync(self, *args, bz_api_key, **kwargs):
        """
        Bugzilla sync of the Affect instance
        """
        self.save()
        # Affect needs to be synced through flaw
        self.flaw.save(*args, bz_api_key=bz_api_key, **kwargs)


class TrackerManager(ACLMixinManager, TrackingMixinManager):
    """tracker manager"""

    @staticmethod
    def create_tracker(affect, external_system_id, _type, **extra_fields):
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
            tracker.save()
        if affect is not None:
            tracker.affects.add(affect)
        return tracker


class Tracker(AlertMixin, TrackingMixin, NullStrFieldsMixin, ACLMixin):
    """tracker model definition"""

    class TrackerType(models.TextChoices):
        """allowable bts name"""

        JIRA = "JIRA"
        BUGZILLA = "BUGZILLA"

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # type
    type = models.CharField(choices=TrackerType.choices, max_length=100)

    # key
    external_system_id = models.CharField(max_length=100)

    # BTS status:resolution context
    # the values are dependent on the BTS
    status = models.CharField(max_length=100)
    resolution = models.CharField(max_length=100, blank=True)
    ps_update_stream = models.CharField(max_length=100, blank=True)

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
        unique_together = ["type", "external_system_id"]
        indexes = TrackingMixin.Meta.indexes

    objects = TrackerManager()

    def __str__(self):
        return str(self.uuid)

    def _validate_tracker_flaw_accesses(self):
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

    def _validate_notaffected_open_tracker(self):
        """
        Check whether notaffected products have open trackers.
        """
        affect = self.affects.filter(
            affectedness=Affect.AffectAffectedness.NOTAFFECTED
        ).first()

        if not self.is_closed and affect:
            raise ValidationError(
                f"Affect ({affect.uuid}) for {affect.ps_module}/{affect.ps_component} is marked as "
                "NOTAFFECTED but has open tracker(s).",
            )

    def _validate_wontfix_open_tracker(self):
        """
        Check whether wontfix affects have open trackers.
        """
        affect = self.affects.filter(resolution=Affect.AffectResolution.WONTFIX).first()
        if not self.is_closed and affect:
            raise ValidationError(
                f"Affect ({affect.uuid}) for {affect.ps_module}/{affect.ps_component} is marked as "
                "WONTFIX but has open tracker(s).",
            )

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
            elif self.resolution in ("notabug", "not a bug", "rejected"):
                return Affect.AffectFix.NOTAFFECTED
            elif self.resolution in ("eol", "out of date"):
                return Affect.AffectFix.OOSS
            elif self.resolution in ("deferred", "nextrelease", "rawhide", "upstream"):
                return Affect.AffectFix.DEFER
        return Affect.AffectFix.AFFECTED

    @property
    def is_closed(self):
        return self.status.upper() == "CLOSED"


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

    # TrackingMixin's updated_dt keeps track of the last time we refreshed an erratum from Errata Tool

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


class FlawMetaManager(ACLMixinManager, TrackingMixinManager):
    """flawmeta manager"""

    @staticmethod
    def create_flawmeta(flaw, _type, meta, **extra_fields):
        """return a new flawmeta or update an existing flawmeta without saving"""
        try:
            flawmeta = FlawMeta.objects.get(flaw=flaw, type=_type, meta_attr=meta)
            for attr, value in extra_fields.items():
                setattr(flawmeta, attr, value)
            return flawmeta
        except ObjectDoesNotExist:
            return FlawMeta(
                flaw=flaw,
                type=_type,
                meta_attr=meta,
                **extra_fields,
            )


class FlawMeta(AlertMixin, TrackingMixin, ACLMixin):
    """Model representing extensible structured flaw metadata"""

    class FlawMetaType(models.TextChoices):
        """allowable types"""

        ERRATA = "ERRATA"
        REFERENCE = "REFERENCE"
        ACKNOWLEDGMENT = "ACKNOWLEDGMENT"
        EXPLOIT = "EXPLOIT"
        MAJOR_INCIDENT = "MAJOR_INCIDENT"
        MAJOR_INCIDENT_LITE = "MAJOR_INCIDENT_LITE"
        REQUIRES_SUMMARY = "REQUIRES_SUMMARY"
        NIST_CVSS_VALIDATION = "NIST_CVSS_VALIDATION"
        NEED_INFO = "NEED_INFO"
        CHECKLIST = "CHECKLIST"
        NVD_CVSS = "NVD_CVSS"

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    type = models.CharField(choices=FlawMetaType.choices, max_length=500)

    # non operational meta data
    meta_attr = HStoreField(default=dict)

    # A Flaw can have many structured FlawMeta
    flaw = models.ForeignKey(Flaw, on_delete=models.CASCADE, related_name="meta")

    objects = FlawMetaManager()

    class Meta:
        """define meta"""

        verbose_name = "FlawMeta"

    def __str__(self):
        return str(self.uuid)

    def _validate_major_incident_combos(self):
        """
        Checks that the combination of MAJOR_INCIDENT and MAJOR_INCIDENT_LITE is valid.
        """
        if self.type not in (
            self.FlawMetaType.MAJOR_INCIDENT,
            self.FlawMetaType.MAJOR_INCIDENT_LITE,
        ):
            return

        INVALID_COMBOS = [("+", "+"), ("+", "?"), ("?", "+"), ("?", "-"), ("-", "?")]
        maj_incident_flag = None
        maj_incident_lite_flag = None

        # must include self as it's potentially not yet included in flaw.meta.all()
        for meta in list(self.flaw.meta.all()) + [self]:
            if meta.type == FlawMeta.FlawMetaType.MAJOR_INCIDENT:
                maj_incident_flag = meta.meta_attr.get("status")
            if meta.type == FlawMeta.FlawMetaType.MAJOR_INCIDENT_LITE:
                maj_incident_lite_flag = meta.meta_attr.get("status")
            if maj_incident_flag and maj_incident_lite_flag:
                break

        flag_pair = (maj_incident_flag, maj_incident_lite_flag)
        if flag_pair in INVALID_COMBOS:
            raise ValidationError(
                f"Flaw MAJOR_INCIDENT and MAJOR_INCIDENT_LITE combination cannot be {flag_pair}."
            )

    def _validate_public_source_no_ack(self):
        """
        Checks that ACK FlawMetas cannot be linked to flaws with public sources.
        """
        if self.type != self.FlawMetaType.ACKNOWLEDGMENT or not self.flaw.source:
            return

        if (source := FlawSource(self.flaw.source)) and source.is_public():
            if source.is_private():
                self.alert(
                    "public_source_no_ack",
                    f"Flaw source of type {source} can be public or private, "
                    "ensure that it is private since the Flaw has acknowledgments.",
                )
            else:
                raise ValidationError(
                    f"Flaw contains acknowledgments for public source {self.flaw.source}"
                )


class FlawCommentManager(ACLMixinManager, TrackingMixinManager):
    """flawcomment manager"""

    @staticmethod
    def create_flawcomment(flaw, external_system_id, comment, **extra_fields):
        """return a new flawcomment or update an existing flawcomment without saving"""
        try:
            flawcomment = FlawComment.objects.get(
                flaw=flaw, external_system_id=external_system_id
            )
            flawcomment.meta_attr = comment
            return flawcomment
        except ObjectDoesNotExist:
            return FlawComment(
                flaw=flaw,
                external_system_id=external_system_id,
                meta_attr=comment,
                **extra_fields,
            )


class FlawComment(TrackingMixin, ACLMixin):
    """Model representing flaw comments"""

    class FlawCommentType(models.TextChoices):
        """allowable types"""

        BUGZILLA = "BUGZILLA"

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # comment type
    type = models.CharField(
        default=FlawCommentType.BUGZILLA,
        choices=FlawCommentType.choices,
        max_length=100,
    )

    # external comment id
    external_system_id = models.CharField(max_length=100)

    # explicitly define comment ordering, from BZ comment 'count'
    order = models.IntegerField(null=True)

    # text of the comment
    text = models.TextField()

    # comment meta data
    meta_attr = HStoreField(default=dict)

    # one flaw can have many comments
    flaw = models.ForeignKey(Flaw, on_delete=models.CASCADE, related_name="comments")

    objects = FlawCommentManager()

    def __str__(self):
        return str(self.uuid)

    class Meta:
        """define meta"""

        ordering = (
            "order",
            "external_system_id",
            "created_dt",
        )


class VersionStatus(models.TextChoices):
    AFFECTED = "AFFECTED"
    UNAFFECTED = "UNAFFECTED"
    UNKNOWN = "UNKNOWN"


class Version(PolymorphicModel):
    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        """define meta"""

        verbose_name = "Version"

    def validate(self, *args, **kwargs):
        """validate versionRange model"""
        super().clean_fields(*args, **kwargs)


# See CVE v5 reporting schema
# https://gist.github.com/rsc/0b448f99e73bf745eeca1319d882efb2#versions-and-version-ranges
class CVEv5Version(Version):
    """Model representing a package version"""

    # TODO add type and comparison fields
    # We didn't add it yet because exisiting BZ data is not accurate
    # enough to determine type (eg. semver, rpm) consistently
    # should should be based on collection_url or entered manually

    version = models.CharField(max_length=1024)

    status = models.CharField(choices=VersionStatus.choices, max_length=20)


class PackageVersions(PolymorphicModel):
    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    flaw = models.ForeignKey(
        Flaw,
        related_name="package_versions",
        on_delete=models.CASCADE,
    )

    versions = models.ManyToManyField(Version)

    class Meta:
        """define meta"""

        verbose_name = "Package Versions"

    def validate(self, *args, **kwargs):
        """validate package versions model"""
        super().clean_fields(*args, **kwargs)


class CVEv5PackageVersions(PackageVersions):

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

    def __str__(self):
        return self.package


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
    private_tracker_cc = fields.ArrayField(
        models.CharField(max_length=50), default=list, blank=True
    )
    component_cc = models.JSONField(default=dict, blank=True)

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
    bz_username = models.CharField(max_length=100)
    jboss_username = models.CharField(max_length=100)


class Profile(models.Model):
    user = models.OneToOneField(
        User,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    bz_user_id = models.CharField(max_length=100, blank=True)
    jira_user_id = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return self.username


from apps.bbsync.cc import AffectCCBuilder, RHSCLAffectCCBuilder  # noqa: E402

from .constants import (  # noqa: E402
    AFFECTEDNESS_VALID_RESOLUTIONS,
    BZ_ID_SENTINEL,
    COMPONENTS_WITHOUT_COLLECTION,
    CVSS3_SEVERITY_SCALE,
    OSIDB_API_VERSION,
    SERVICES_PRODUCTS,
)
