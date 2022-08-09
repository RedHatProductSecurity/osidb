"""
draft model for end to end testing
"""
import logging
import uuid
from decimal import Decimal
from typing import Union

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.postgres import fields
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from polymorphic.models import PolymorphicModel
from psqlextra.fields import HStoreField

from apps.exploits.mixins import AffectExploitExtensionMixin
from apps.exploits.query_sets import AffectQuerySetExploitExtension
from apps.osim.workflow import WorkflowModel

from .constants import CVSS3_SEVERITY_SCALE, OSIDB_API_VERSION
from .core import generate_acls
from .mixins import NullStrFieldsMixin, TrackingMixin
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


class FlawHistoryManager(models.Manager):
    """flaw history manager"""

    def get_queryset(self):
        """define base queryset for retrieving flaws"""
        return (
            super()
            .get_queryset()
            .annotate(
                # annotate queryset with embargoed pseudo-attribute as it is fully based on the ACLs
                embargoed=models.Case(
                    models.When(
                        acl_read=[
                            uuid.UUID(acl)
                            for acl in generate_acls([settings.EMBARGO_READ_GROUP])
                        ],
                        then=True,
                    ),
                    default=False,
                    output_field=models.BooleanField(),
                )
            )
        )

    @staticmethod
    def fts_search(q):
        """full text search using postgres FTS via django.contrib.postgres"""
        return search_helper(FlawHistory.objects.get_queryset(), (), q)
        # Search default Flaw fields (title, description, summary, statement) with default weights
        # If search has no results, this will now return an empty queryset


class FlawType(models.TextChoices):
    """allowable types"""

    VULN = "VULNERABILITY"
    WEAK = "WEAKNESS"


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

    def is_public(self):
        """
        Returns True if the source is public, False otherwise.

        Note that the following sources can be both public and private, but for
        validation purposes we don't treat them as private:

        MAGEIA, DEBIAN, GENTOO, SUSE, UBUNTU
        """
        return self not in {
            # PRIVATE_SOURCES from SFM2
            self.ADOBE,
            self.APPLE,
            self.CERT,
            self.CUSTOMER,
            self.DISTROS,
            self.GOOGLE,
            self.MOZILLA,
            self.OPENSSL,
            self.REDHAT,
            self.RESEARCHER,
            self.SECUNIA,
            self.UPSTREAM,
            self.XEN,
            self.VENDOR_SEC,
            self.SUN,
            self.HW_VENDOR,
        }


class FlawHistory(NullStrFieldsMixin):
    """match existing history table for flaws"""

    pgh_created_at = models.DateTimeField(null=True)
    # this model is unused so we don't care that it's a CharField with null=True
    pgh_label = models.CharField(max_length=100, null=True)  # noqa: DJ01

    class FlawHistoryState(models.TextChoices):
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

    class FlawMitigate(models.TextChoices):
        """allowable mitigated_by"""

        SELINUX = "SELINUX"
        FORTIFY = "FORTIFY"
        GRSEC = "GRSEC"

    class FlawHistoryResolution(models.TextChoices):
        """allowable resolution"""

        NOVALUE = ""
        FIX = "FIX"
        DEFER = "DEFER"
        WONTFIX = "WONTFIX"
        OOSS = "OOSS"

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # CVE-ID, should be unique, from BZ alias
    cve_id = models.CharField(max_length=500, blank=True)

    # vulnerability or weakness
    type = models.CharField(
        choices=FlawType.choices, default=FlawType.VULN, max_length=20
    )

    # flaw state, from BZ status
    state = models.CharField(
        choices=FlawHistoryState.choices, default=FlawHistoryState.NEW, max_length=100
    )

    # resolution
    resolution = models.CharField(
        choices=FlawResolution.choices,
        default=FlawResolution.NOVALUE,
        max_length=100,
        blank=True,
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

    # , from srtnotes "mitigate"
    mitigated_by = models.CharField(
        choices=FlawMitigate.choices, max_length=10, blank=True
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

    acl_read = fields.ArrayField(models.UUIDField(), default=list)
    acl_write = fields.ArrayField(models.UUIDField(), default=list)

    # non operational meta data
    meta_attr = HStoreField(default=dict)

    class Meta:
        """define meta"""

        verbose_name = "FlawHistory"

    def __str__(self):
        return str(self.cve_id)

    objects = FlawHistoryManager()

    def validate(self, *args, **kwargs):
        """validate flaw model"""
        # add custom validation here
        self.clean()
        # self.full_clean(*args, exclude=["meta_attr"], **kwargs)

    def save(self, *args, **kwargs):
        """save model override"""
        self.validate()
        # TODO see process_embargo_state
        # if ENABLE_EMBARGO_PROCESS:
        #     self.process_embargo_state()
        super().save(*args, **kwargs)

    # TODO this needs to be refactored
    # but it makes sense only when we are capable of write actions
    # and we may thus actually do some changes to the embargo
    #
    # def process_embargo_state(self):
    #     """TBD - this is process related so deactivating it

    #     explicitly set embargoed based on co-constraints

    #     embargoed = (True|False|None)
    #     unembargo_dt = (Past date|Future date | None)
    #     # permutations = 9

    #     | embargoed | unembargo_dt | embargoed set value |
    #     |-----------|--------------|---------------------|
    #     | True      | None         | True                |
    #     | False     | None         | False               |
    #     | None      | None         | False               |

    #     | True      | Future date  | True                |
    #     | False     | Future date  | True                |
    #     | None      | Future date  | True                |

    #     | True      | Past date    | True                | no trust defensive - in the future we may change
    #     | False     | Past date    | False               |
    #     | None      | Past date    | False               |

    #     corner case(s) = [ unembargo_dt = now() ]

    #     TBD -  process with respect to perms access

    #     """
    #     if self.embargoed and self.unembargo_dt is None:
    #         pass
    #     elif self.embargoed and self.unembargo_dt < datetime.now():
    #         pass
    #     elif self.unembargo_dt is None:
    #         self.embargoed = False
    #     else:
    #         if self.unembargo_dt > datetime.now():
    #             self.embargoed = True
    #         if self.unembargo_dt < datetime.now():
    #             self.embargoed = False


class FlawManager(models.Manager):
    """flaw manager"""

    @staticmethod
    def create_flaw(cve_id, **extra_fields):
        """return a new flaw or update an existing flaw without saving"""
        try:
            flaw = Flaw.objects.get(cve_id=cve_id)
            for attr, value in extra_fields.items():
                setattr(flaw, attr, value)
            return flaw
        except ObjectDoesNotExist:
            return Flaw(cve_id=cve_id, **extra_fields)

    def get_queryset(self):
        """define base queryset for retrieving flaws"""
        return (
            super()
            .get_queryset()
            .annotate(
                # annotate queryset with embargoed pseudo-attribute as it is fully based on the ACLs
                embargoed=models.Case(
                    models.When(
                        acl_read=[
                            uuid.UUID(acl)
                            for acl in generate_acls([settings.EMBARGO_READ_GROUP])
                        ],
                        then=True,
                    ),
                    default=False,
                    output_field=models.BooleanField(),
                )
            )
        )

    @staticmethod
    def fts_search(q):
        """full text search using postgres FTS via django.contrib.postgres"""
        return search_helper(Flaw.objects.get_queryset(), (), q)
        # Search default Flaw fields (title, description, summary, statement) with default weights
        # If search has no results, this will now return an empty queryset


class Flaw(WorkflowModel, TrackingMixin, NullStrFieldsMixin):
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

    class FlawMitigate(models.TextChoices):
        """allowable mitigate"""

        SELINUX = "SELINUX"
        FORTIFY = "FORTIFY"

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # CVE-ID, should be unique, from BZ alias
    cve_id = models.CharField(
        max_length=500,
        null=True,
        unique=True,
        validators=[validate_cve_id],
        blank=True,
    )

    # vulnerability or weakness
    type = models.CharField(
        choices=FlawType.choices, default=FlawType.VULN, max_length=20
    )

    # flaw state, from BZ status
    state = models.CharField(
        choices=FlawState.choices, default=FlawState.NEW, max_length=100
    )

    # resolution
    resolution = models.CharField(
        choices=FlawResolution.choices,
        default=FlawResolution.NOVALUE,
        max_length=100,
        blank=True,
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

    # reported source of flaw, from srtnotes "source"
    source = models.CharField(choices=FlawSource.choices, max_length=500, blank=True)

    # reported date, from srtnotes "reported"
    reported_dt = models.DateTimeField(
        null=True, blank=True, validators=[no_future_date]
    )

    # , from srtnotes "mitigate"
    mitigated_by = models.CharField(
        choices=FlawMitigate.choices, max_length=10, blank=True
    )

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

    acl_read = fields.ArrayField(models.UUIDField(), default=list)
    acl_write = fields.ArrayField(models.UUIDField(), default=list)

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
        """return cve_id when str(flaw)"""
        return str(self.cve_id)

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
            raise ValidationError(
                f"RH and NVD CVSSv3 score differs by 1.0 or more - "
                f"RH {rh_cvss3_score} | NVD {nvd_cvss3_score}"
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
            raise ValidationError(
                "RH and NVD CVSSv3 score difference crosses severity boundary - "
                f"RH {rh_cvss3_score}:{rh_severity} | "
                f"NVD {nvd_cvss3_score}:{nvd_severity}"
            )

    def _validate_embargoed_source(self):
        """
        Checks that the source is private if the Flaw is embargoed.
        """
        if not self.source:
            return
        # TODO: make embargoed accessible from python code (property?)
        embargoed = self.acl_read == [
            uuid.UUID(acl) for acl in generate_acls([settings.EMBARGO_READ_GROUP])
        ]
        if embargoed and FlawSource(self.source).is_public():
            raise ValidationError(
                f"Flaw is embargoed but contains public source: {self.source}"
            )

    def validate(self, *args, **kwargs):
        """validate flaw model"""
        self.full_clean(*args, exclude=["meta_attr"], **kwargs)
        # add custom validation here
        self._validate_rh_nvd_cvss_score_diff()
        self._validate_rh_nvd_cvss_severity_diff()
        self._validate_embargoed_source()

    def save(self, *args, **kwargs):
        """save model override"""
        self.validate()
        # TODO see process_embargo_state
        # if ENABLE_EMBARGO_PROCESS:
        #     self.process_embargo_state()
        super().save(*args, **kwargs)

    # TODO this needs to be refactored
    # but it makes sense only when we are capable of write actions
    # and we may thus actually do some changes to the embargo
    #
    # def process_embargo_state(self):
    #     """TBD - this is process related so deactivating it

    #     explicitly set embargoed based on co-constraints

    #     embargoed = (True|False|None)
    #     unembargo_dt = (Past date|Future date | None)
    #     # permutations = 9

    #     | embargoed | unembargo_dt | embargoed set value |
    #     |-----------|--------------|---------------------|
    #     | True      | None         | True                |
    #     | False     | None         | False               |
    #     | None      | None         | False               |

    #     | True      | Future date  | True                |
    #     | False     | Future date  | True                |
    #     | None      | Future date  | True                |

    #     | True      | Past date    | True                | no trust defensive - in the future we may change
    #     | False     | Past date    | False               |
    #     | None      | Past date    | False               |

    #     corner case(s) = [ unembargo_dt = now() ]

    #     TBD -  process with respect to perms access

    #     """
    #     if self.embargoed and self.unembargo_dt is None:
    #         pass
    #     elif self.embargoed and self.unembargo_dt < datetime.now():
    #         pass
    #     elif self.unembargo_dt is None:
    #         self.embargoed = False
    #     else:
    #         if self.unembargo_dt > datetime.now():
    #             self.embargoed = True
    #         if self.unembargo_dt < datetime.now():
    #             self.embargoed = False

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


class AffectManager(models.Manager):
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

    def get_queryset(self):
        """define base queryset for retrieving affects"""
        return super().get_queryset()

    @staticmethod
    def fts_search(q):
        """full text search using postgres FTS via django.contrib.postgres"""
        fields_to_search = (
            "cve_id",
            "ps_component",
            "ps_module",
            "resolution",
            "affectedness",
            "type",
        )
        return search_helper(Affect.objects.get_queryset(), fields_to_search, q)
        # Search Affect fields specified with equal weights
        # If search has no results, this will now return an empty queryset


class Affect(TrackingMixin, AffectExploitExtensionMixin, NullStrFieldsMixin):
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
    ps_component = models.CharField(max_length=100)

    # from srtnotes affects/impact
    impact = models.CharField(choices=AffectImpact.choices, max_length=500, blank=True)

    # from srtnotes affects/cvss2
    cvss2 = models.CharField(max_length=100, blank=True, validators=[validate_cvss2])
    cvss2_score = models.FloatField(null=True, blank=True)

    # from srtnotes affects/cvss3
    cvss3 = models.CharField(max_length=100, blank=True, validators=[validate_cvss3])
    cvss3_score = models.FloatField(null=True, blank=True)

    # non operational meta data
    meta_attr = HStoreField(default=dict)

    acl_read = fields.ArrayField(models.UUIDField(), default=list)
    acl_write = fields.ArrayField(models.UUIDField(), default=list)

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
        indexes = TrackingMixin.Meta.indexes

    # objects = AffectManager()
    objects = AffectManager.from_queryset(AffectQuerySetExploitExtension)()

    def __str__(self):
        return str(self.uuid)

    def validate(self, *args, **kwargs):
        """validate model"""
        self.full_clean(*args, exclude=["meta_attr"], **kwargs)

    def save(self, *args, **kwargs):
        """save model override"""
        self.validate()
        super().save(*args, **kwargs)

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


class TrackerManager(models.Manager):
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

    def get_queryset(self):
        """define base queryset for retrieving trackers"""
        return super().get_queryset()


class Tracker(TrackingMixin, NullStrFieldsMixin):
    """tracker model definition"""

    class TrackerType(models.TextChoices):
        """allowable bts name"""

        JIRA = "JIRA"
        BZ = "BUGZILLA"

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

    acl_read = fields.ArrayField(models.UUIDField(), default=list)
    acl_write = fields.ArrayField(models.UUIDField(), default=list)

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

    def validate(self, *args, **kwargs):
        """validate model"""
        self.full_clean(*args, exclude=["meta_attr"], **kwargs)

    def save(self, *args, **kwargs):
        """save model override"""
        self.validate()
        super().save(*args, **kwargs)

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

    class Meta:
        verbose_name = "Erratum"
        verbose_name_plural = "Errata"

    def __str__(self):
        # self.advisory_name is already a str, below needed only to fix a warning
        return str(self.advisory_name)


class FlawMetaManager(models.Manager):
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

    def get_queryset(self):
        """define base queryset for retrieving flawmeta, order by oldest date first"""
        return super().get_queryset()


class FlawMeta(TrackingMixin):
    """Model representing extensible structured flaw metadata"""

    class FlawMetaType(models.TextChoices):
        """allowable types"""

        ERRATA = "ERRATA"
        REFERENCE = "REFERENCE"
        ACKNOWLEDGMENT = "ACKNOWLEDGMENT"
        EXPLOIT = "EXPLOIT"
        MAJOR_INCIDENT = "MAJOR_INCIDENT"
        MAJOR_INCIDENT_LITE = "MAJOR_INCIDENT_LITE"
        REQUIRES_DOC_TEXT = "REQUIRES_DOC_TEXT"
        NIST_CVSS_VALIDATION = "NIST_CVSS_VALIDATION"
        NEED_INFO = "NEED_INFO"
        CHECKLIST = "CHECKLIST"
        NVD_CVSS = "NVD_CVSS"

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    type = models.CharField(choices=FlawMetaType.choices, max_length=500)

    # non operational meta data
    meta_attr = HStoreField(default=dict)

    acl_read = fields.ArrayField(models.UUIDField(), default=list)
    acl_write = fields.ArrayField(models.UUIDField(), default=list)

    # A Flaw can have many structured FlawMeta
    flaw = models.ForeignKey(
        Flaw, null=True, on_delete=models.CASCADE, related_name="meta"
    )

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

        if FlawSource(self.flaw.source).is_public():
            raise ValidationError(
                f"Flaw contains acknowledgments for public source {self.flaw.source}"
            )

    def validate(self, *args, **kwargs):
        """validate model"""
        # add custom validation here
        super().clean_fields(*args, exclude=["meta_attr"], **kwargs)
        self._validate_major_incident_combos()
        self._validate_public_source_no_ack()

    def save(self, *args, **kwargs):
        """save model override"""
        self.validate()
        # TODO see process_embargo_state
        # if ENABLE_EMBARGO_PROCESS:
        #     self.process_embargo_state()
        super().save(*args, **kwargs)


class FlawCommentManager(models.Manager):
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

    def get_queryset(self):
        """define base queryset for retrieving flawcomment, order by oldest date first"""
        return super().get_queryset()


class FlawComment(TrackingMixin):
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

    acl_read = fields.ArrayField(models.UUIDField(), default=list)
    acl_write = fields.ArrayField(models.UUIDField(), default=list)

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


class PsModule(NullStrFieldsMixin):

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
    unacked_ps_update_stream = models.CharField(max_length=100, blank=True)

    ps_product = models.ForeignKey(
        PsProduct, on_delete=models.CASCADE, related_name="ps_modules"
    )

    def validate(self, *args, **kwargs):
        """validate model"""
        # add custom validation here
        self.full_clean(*args, **kwargs)

    def save(self, *args, **kwargs):
        """save model override"""
        self.validate()
        super().save(*args, **kwargs)


class PsUpdateStream(NullStrFieldsMixin):

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

    def validate(self, *args, **kwargs):
        """validate model"""
        # add custom validation here
        self.full_clean(*args, **kwargs)

    def save(self, *args, **kwargs):
        """save model override"""
        self.validate()
        super().save(*args, **kwargs)


class PsContact(NullStrFieldsMixin):

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # base RedHat username, also known as id in SFM2
    username = models.CharField(max_length=100, unique=True)

    # BTS usernames
    bz_username = models.CharField(max_length=100)
    jboss_username = models.CharField(max_length=100)

    def validate(self, *args, **kwargs):
        """validate model"""
        # add custom validation here
        self.full_clean(*args, **kwargs)

    def save(self, *args, **kwargs):
        """save model override"""
        self.validate()
        super().save(*args, **kwargs)


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
