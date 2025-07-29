import logging
import re
import uuid

import pghistory
from django.contrib.postgres import fields
from django.contrib.postgres.indexes import GinIndex
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from packageurl import PackageURL
from psqlextra.fields import HStoreField

from apps.bbsync.constants import RHSCL_BTS_KEY
from apps.bbsync.mixins import BugzillaSyncMixin
from apps.bbsync.models import BugzillaComponent
from apps.exploits.mixins import AffectExploitExtensionMixin
from apps.exploits.query_sets import AffectQuerySetExploitExtension
from osidb.mixins import (
    ACLMixin,
    ACLMixinManager,
    AlertMixin,
    NullStrFieldsMixin,
    TrackingMixin,
    TrackingMixinManager,
)
from osidb.models.fields import CVEIDField
from osidb.query_sets import CustomQuerySetUpdatedDt

from .abstract import CVSS, Impact
from .flaw.flaw import Flaw
from .ps_constants import SpecialConsiderationPackage
from .ps_module import PsModule
from .ps_update_stream import PsUpdateStream

logger = logging.getLogger(__name__)


class NotAffectedJustification(models.TextChoices):
    """Valid choices for not affected justifications in affects and trackers."""

    NOVALUE = ""
    COMPONENT_NOT_PRESENT = "Component not Present"
    INLINE_MITIGATIONS_ALREADY_EXIST = "Inline Mitigations already Exist"
    VULN_CODE_CANNOT_BE_CONTROLLED = "Vulnerable Code cannot be Controlled by Adversary"
    VULN_CODE_NOT_IN_EXECUTE_PATH = "Vulnerable Code not in Execute Path"
    VULN_CODE_NOT_PRESENT = "Vulnerable Code not Present"


class AffectManager(ACLMixinManager, TrackingMixinManager):
    """affect manager"""

    def get_queryset(self):
        return (
            super()
            .get_queryset()
            .prefetch_related(
                "tracker",
            )
            .annotate(
                ps_product_name=models.Subquery(
                    PsModule.objects.filter(name=models.OuterRef("ps_module")).values(
                        "ps_product__name"
                    )
                )
            )
        )

    @staticmethod
    def create_affect(flaw, ps_update_stream, ps_component, **extra_fields):
        """return a new affect or update an existing affect without saving"""

        try:
            affect = Affect.objects.get(
                flaw=flaw, ps_update_stream=ps_update_stream, ps_component=ps_component
            )
            for attr, value in extra_fields.items():
                setattr(affect, attr, value)
            return affect
        except ObjectDoesNotExist:
            return Affect(
                flaw=flaw,
                ps_update_stream=ps_update_stream,
                ps_component=ps_component,
                **extra_fields,
            )

    @staticmethod
    def fts_search(q):
        """full text search using postgres FTS via django.contrib.postgres"""
        from osidb.filters import search_helper

        fields_to_search = (
            "ps_component",
            "ps_update_stream",
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
    exclude="meta_attr",
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

    # CVE id denormalized from parent flaw, should not be manually set
    cve_id = CVEIDField(unique=False)

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

    ps_update_stream = models.CharField()
    # ps_module is denormalized as it is still used extensively
    ps_module = models.CharField(blank=True)

    tracker = models.ForeignKey(
        "Tracker",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="affects",
    )

    # the length 255 does not have any special meaning in Postgres
    # but it is the maximum SFM2 value so let us just keep parity for now
    # to fix https://issues.redhat.com/browse/OSIDB-635
    ps_component = models.CharField(max_length=255)

    purl = models.TextField(blank=True)

    impact = models.CharField(choices=Impact.choices, max_length=20, blank=True)

    not_affected_justification = models.CharField(
        choices=NotAffectedJustification.choices, max_length=100, blank=True
    )

    resolved_dt = models.DateTimeField(null=True, blank=True)

    # non operational meta data
    meta_attr = HStoreField(default=dict)

    # A Flaw can have many Affects
    flaw = models.ForeignKey(Flaw, on_delete=models.CASCADE, related_name="affects")

    class Meta:
        """define meta"""

        unique_together = ("flaw", "ps_update_stream", "ps_component")
        ordering = (
            "created_dt",
            "uuid",
        )
        verbose_name = "Affect"
        indexes = TrackingMixin.Meta.indexes + [
            models.Index(fields=["cve_id"]),
            models.Index(fields=["flaw", "ps_update_stream"]),
            models.Index(fields=["flaw", "ps_component"]),
            GinIndex(fields=["acl_read"]),
        ]

    # objects = AffectManager()
    objects = AffectManager.from_queryset(AffectQuerySetExploitExtension)()

    def __str__(self):
        return str(self.uuid)

    def ps_component_from_purl(self, should_raise=False):
        try:
            # try to parse the PS component from the PURL but do not raise any
            # error on failure as that will be done as part of the validations
            purl = PackageURL.from_string(self.purl)
            if purl.type == "oci":
                try:
                    prefix = purl.qualifiers["repository_url"].split("/")[1]
                    return f"{prefix}/{purl.name}"
                except (KeyError, IndexError):
                    raise ValueError("Invalid repository_url in OCI PURL")
            elif "rpmmod" in purl.qualifiers:
                return f"{purl.qualifiers['rpmmod']}/{purl.name}"
            else:
                return purl.name
        except ValueError:
            if should_raise:
                raise
            else:
                pass

    def save(self, *args, **kwargs):
        if self.purl and not self.ps_component:
            try:
                maybe_ps_component = self.ps_component_from_purl()
                if maybe_ps_component:
                    self.ps_component = maybe_ps_component
            except ValueError:
                pass

        if self.is_resolved:
            if self._state.adding:
                # new affect created resolved
                self.resolved_dt = timezone.now().replace(microsecond=0)
            else:
                old_affect = Affect.objects.get(uuid=self.uuid)
                if not old_affect.is_resolved:
                    # affect changed from unresolved to resolved
                    self.resolved_dt = timezone.now().replace(microsecond=0)
        else:
            # Not resolved affects should never have resolved_dt
            self.resolved_dt = None

        ps_update_stream = PsUpdateStream.objects.filter(
            name=self.ps_update_stream
        ).first()
        if ps_update_stream:
            self.ps_module = ps_update_stream.ps_module.name
        else:
            self.ps_module = None

        super().save(*args, **kwargs)

    def _validate_ps_module_old_flaw(self, **kwargs):
        """
        Checks that an affect from an older flaw contains a valid ps_module.

        This method will only generate an alert and will not raise a ValidationError,
        this is because there is legacy data in external systems that we pull from
        (i.e. BZ) that worked under a different system (ps_update_stream instead of
        ps_module for affects) and thus raising a ValidationError would make legacy
        flaws unupdatable.
        """
        from osidb.constants import BZ_ID_SENTINEL

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
        from osidb.constants import BZ_ID_SENTINEL

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
        from osidb.constants import COMPONENTS_WITHOUT_COLLECTION

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
                    f"Affect ({self.uuid}) for {self.ps_update_stream}/{self.ps_component} has an invalid "
                    f"affectedness/resolution combination: {self.resolution} is not a valid resolution "
                    f"for {self.affectedness}."
                )

            # If modifying something else from a record with an invalid combination, e.g. the
            # impact, throw an alert
            self.alert(
                "flaw_historical_affect_status",
                f"Affect ({self.uuid}) for {self.ps_update_stream}/{self.ps_component} has a "
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
                f"Affect ({self.uuid}) for {self.ps_update_stream}/{self.ps_component} has an invalid "
                f"affectedness/resolution combination: {self.resolution} is not a valid resolution "
                f"for {self.affectedness}."
            )

    def _validate_notaffected_open_tracker(self, **kwargs):
        """
        Check whether notaffected products have open trackers.
        """
        if (
            self.affectedness == Affect.AffectAffectedness.NOTAFFECTED
            and self.tracker is not None
            and self.tracker.status != "CLOSED"  # see tracker.is_closed
        ):
            raise ValidationError(
                f"Affect ({self.uuid}) for {self.ps_update_stream}/{self.ps_component} is marked as "
                "NOTAFFECTED but has open tracker(s).",
            )

    def _validate_ooss_open_tracker(self, **kwargs):
        """
        Check whether out of support scope products have open trackers.
        """
        if (
            self.resolution == Affect.AffectResolution.OOSS
            and self.tracker is not None
            and self.tracker.status != "CLOSED"  # see tracker.is_closed
        ):
            raise ValidationError(
                f"Affect ({self.uuid}) for {self.ps_update_stream}/{self.ps_component} is marked as "
                "OOSS but has open tracker(s).",
            )

    def _validate_wontfix_open_tracker(self, **kwargs):
        """
        Check whether wontfix affects have open trackers.
        """
        if (
            self.resolution == Affect.AffectResolution.WONTFIX
            and self.tracker is not None
            and self.tracker.status != "CLOSED"  # see tracker.is_closed
        ):
            raise ValidationError(
                f"Affect ({self.uuid}) for {self.ps_update_stream}/{self.ps_component} is marked as "
                "WONTFIX but has open tracker(s).",
            )

    def _validate_defer_open_trackers(self, **kwargs):
        """
        Prevent an affect with open trackers from having a resolution of DEFER
        """
        if (
            self.resolution == Affect.AffectResolution.DEFER
            and self.tracker is not None
            and self.tracker.status != "CLOSED"  # see tracker.is_closed
        ):
            raise ValidationError(
                f"Affect ({self.uuid}) for {self.ps_update_stream}/{self.ps_component} cannot have "
                "resolution DEFER with open tracker(s).",
            )

    def _validate_unknown_component(self, **kwargs):
        """
        Alerts that a flaw affects a component not tracked in Bugzilla.
        Alternatively, the PSComponent should have an override set in Product Definitions.
        The used PSComponent is either misspelled or the override is missing.
        """
        from apps.bbsync.cc import AffectCCBuilder, RHSCLAffectCCBuilder

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
        from osidb.constants import SERVICES_PRODUCTS

        if self.resolution == Affect.AffectResolution.WONTREPORT:
            ps_module = PsModule.objects.filter(name=self.ps_module).first()
            if (
                not ps_module
                or ps_module.ps_product.short_name not in SERVICES_PRODUCTS
            ):
                raise ValidationError(
                    f"Affect ({self.uuid}) for {self.ps_update_stream}/{self.ps_component} is marked as WONTREPORT, "
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
                f"Affect ({self.uuid}) for {self.ps_update_stream}/{self.ps_component} has impact {self.impact} "
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

    def _validate_either_purl_or_ps_component_provided(self, **kwargs) -> None:
        """
        Check that either a PURL or PsComponent has been provided.

        This is essential to determine "what" is affected by a vulnerability.
        """
        if not self.purl and not self.ps_component:
            raise ValidationError(
                f"Affect ({self.uuid}) for {self.ps_update_stream} must have either purl or ps_component."
            )

    def _validate_purl_and_ps_component(self, **kwargs):
        """
        Validate the provided PURL and warn in case of ps_component mismatch.

        This method checks that the PURL is syntactically valid, but also that
        it contains valid required qualifiers.

        It will also emit an alert if the extrapolated ps_component doesn't match
        the provided ps_component.
        """
        if self.purl:
            try:
                ps_component_from_purl = self.ps_component_from_purl(True)
            except ValueError as exc:
                raise ValidationError(
                    f"Affect ({self.uuid}) for {self.ps_update_stream} has "
                    f"an invalid purl '{self.purl}': {exc}."
                )

            if self.ps_component and self.ps_component != ps_component_from_purl:
                self.flaw.alert(
                    "purl_ps_component_mismatch",
                    f"Extrapolated ps_component ({ps_component_from_purl}) "
                    f"from PURL ({self.purl}) "
                    f"does not match user-provided ps_component ({self.ps_component}).",
                )

    def _validate_not_affected_justification(self, **kwargs):
        """
        The not affected justification field becomes mandatory if the affectedness is NOTAFFECTED
        and there are no trackers to compute the justification from.
        If the affectedness is set at a different value than NOTAFFECTED, then the justification should
        be empty.
        """
        if (
            self.affectedness == Affect.AffectAffectedness.NOTAFFECTED
            and not self.not_affected_justification
        ):
            raise ValidationError(
                f"Affect ({self.uuid}) is set as NOTAFFECTED but the 'not affected justification' is empty."
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
        """affect delegated resolution based on the resolution of its related tracker"""
        if not (
            self.affectedness == Affect.AffectAffectedness.AFFECTED
            and self.resolution == Affect.AffectResolution.DELEGATED
        ):
            return None

        # exclude the trackers closed as duplicate or migrated from Bugzilla
        trackers_regex = re.compile(r"(duplicate|migrated)", re.IGNORECASE)
        if not self.tracker or trackers_regex.match(self.tracker.resolution):
            return Affect.AffectFix.AFFECTED

        tracker_status = self.tracker.fix_state
        for status in (
            Affect.AffectFix.AFFECTED,
            Affect.AffectFix.WONTFIX,
            Affect.AffectFix.OOSS,
            Affect.AffectFix.DEFER,
            Affect.AffectFix.NOTAFFECTED,
        ):
            if status == tracker_status:
                if (
                    self.aggregated_impact == Impact.LOW
                    and status == Affect.AffectFix.WONTFIX
                ):
                    # special handling for LOWs
                    return Affect.AffectFix.DEFER

                return status

        # We don't know. Maybe the tracker doesn't have a valid resolution; default to "Affected".
        logger.error("How did we get here??? %s, %s", self.tracker, tracker_status)

        return Affect.AffectFix.AFFECTED

    @property
    def delegated_not_affected_justification(self):
        """
        Delegated not affected justification based on the not affected justification of
        its related Jira tracker.

        If the related tracker is closed as 'Not a Bug' then use its justification, otherwise
        the delegated justification is empty.
        """
        from apps.taskman.service import TaskResolution
        from osidb.models.tracker import Tracker

        if (
            self.tracker is None
            or self.tracker.type == Tracker.TrackerType.JIRA
            or self.tracker.resolution != TaskResolution.NOT_A_BUG
        ):
            return NotAffectedJustification.NOVALUE
        return self.tracker.not_affected_justification

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
    def is_resolved(self) -> bool:
        """
        check and return whether the given affect is considered resolved
        and should have a resolution date
        """
        return (
            self.affectedness not in AFFECTEDNESS_UNRESOLVED_RESOLUTIONS
            or self.resolution
            not in AFFECTEDNESS_UNRESOLVED_RESOLUTIONS[self.affectedness]
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
        if hasattr(self, "ps_product_name"):
            # If the queryset was annotated with ps_product_name, use it
            return self.ps_product_name
        ps_module = PsModule.objects.filter(name=self.ps_module).first()
        if not ps_module:
            return None
        return ps_module.ps_product.name

    def bzsync(self, *args, **kwargs):
        """
        Bugzilla sync of the Affect instance
        """
        self.save()
        # Affect needs to be synced through flaw
        self.flaw.save(*args, **kwargs)


class AffectV1(models.Model):
    """
    Read-only model that maps to the 'affect_v1' database view, used to maintain
    compatibility with v1 of the API.
    """

    uuid = models.UUIDField(primary_key=True, editable=False)
    affectedness = models.CharField(
        max_length=100, choices=Affect.AffectAffectedness.choices
    )
    resolution = models.CharField(
        max_length=100, choices=Affect.AffectResolution.choices
    )
    ps_module = models.CharField(max_length=100)
    ps_component = models.CharField(max_length=255)
    purl = models.TextField(blank=True)
    impact = models.CharField(max_length=20, blank=True, choices=Impact.choices)
    not_affected_justification = models.CharField(max_length=100, blank=True)
    resolved_dt = models.DateTimeField(null=True, blank=True)
    meta_attr = HStoreField(default=dict)
    flaw = models.ForeignKey(
        Flaw, null=True, on_delete=models.DO_NOTHING, db_column="flaw_id"
    )

    # Mirrored fields from mixins
    last_validated_dt = models.DateTimeField(blank=True, default=timezone.now)
    created_dt = models.DateTimeField()
    updated_dt = models.DateTimeField()
    acl_read = fields.ArrayField(models.UUIDField(), default=list)
    acl_write = fields.ArrayField(models.UUIDField(), default=list)

    # Map to the array_agg SQL field that have all the related trackers/cvss scores
    # from the v2 affects
    all_tracker_ids = fields.ArrayField(models.UUIDField(), blank=True, null=True)
    all_cvss_score_ids = fields.ArrayField(models.UUIDField(), blank=True, null=True)

    class Meta:
        managed = False
        db_table = "affect_v1"
        verbose_name = "Affect V1"
        ordering = ["created_dt", "uuid"]

    @property
    def trackers(self):
        from osidb.models import Tracker

        if not self.all_tracker_ids:
            return Tracker.objects.none()
        return Tracker.objects.filter(uuid__in=self.all_tracker_ids)

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
        trackers_regex = re.compile(r"(duplicate|migrated)", re.IGNORECASE)
        trackers = [
            tracker
            for tracker in self.trackers.all()
            if not trackers_regex.match(tracker.resolution)
        ]
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
                if (
                    self.aggregated_impact == Impact.LOW
                    and status == Affect.AffectFix.WONTFIX
                ):
                    # special handling for LOWs
                    return Affect.AffectFix.DEFER

                return status

        # We don't know. Maybe none of the trackers have a valid resolution; default to "Affected".
        logger.error("How did we get here??? %s, %s", trackers, statuses)

        return Affect.AffectFix.AFFECTED

    @property
    def delegated_not_affected_justification(self):
        """
        Delegated not affected justification based on the not affected justifications of
        related Jira trackers.

        If all the trackers related to an affect are closed as 'Not a Bug' and their justifications
        are equal, then pick that value. If they are all closed as 'Not a Bug' but the
        justifications differ, pick 'Component not Present' even if no justification has that
        value.
        If any tracker has a resolution different to 'Not a Bug', then the delegated justification
        becomes empty.
        """
        from apps.taskman.service import TaskResolution
        from osidb.models.tracker import Tracker

        trackers = [
            tracker
            for tracker in self.trackers.all()
            if tracker.type == Tracker.TrackerType.JIRA
        ]
        if not trackers or any(
            tracker
            for tracker in trackers
            if tracker.resolution != TaskResolution.NOT_A_BUG
        ):
            return NotAffectedJustification.NOVALUE

        justifications = [tracker.not_affected_justification for tracker in trackers]
        if len(set(justifications)) == 1:
            return justifications[0]

        return NotAffectedJustification.COMPONENT_NOT_PRESENT

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
    def is_resolved(self) -> bool:
        """
        check and return whether the given affect is considered resolved
        and should have a resolution date
        """
        return (
            self.affectedness not in AFFECTEDNESS_UNRESOLVED_RESOLUTIONS
            or self.resolution
            not in AFFECTEDNESS_UNRESOLVED_RESOLUTIONS[self.affectedness]
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
        if hasattr(self, "ps_product_name"):
            # If the queryset was annotated with ps_product_name, use it
            return self.ps_product_name
        ps_module = PsModule.objects.filter(name=self.ps_module).first()
        if not ps_module:
            return None
        return ps_module.ps_product.name

    # Mirrored properties from mixins
    @property
    def is_embargoed(self):
        return self.acl_read == ACLMixin.get_embargoed_acl()

    @property
    def is_internal(self):
        return set(self.acl_read + self.acl_write) == self.acls_internal

    @property
    def is_public(self):
        return set(self.acl_read + self.acl_write) == self.acls_public


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


@pghistory.track(
    pghistory.InsertEvent(),
    pghistory.UpdateEvent(),
    pghistory.DeleteEvent(),
    model_name="AffectCVSSAudit",
)
class AffectCVSS(CVSS):
    affect = models.ForeignKey(
        Affect, on_delete=models.CASCADE, blank=True, related_name="cvss_scores"
    )

    objects = AffectCVSSManager.from_queryset(CustomQuerySetUpdatedDt)()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["affect", "version", "issuer"], name="unique CVSS of an Affect"
            ),
        ]
        indexes = TrackingMixin.Meta.indexes + [
            GinIndex(fields=["acl_read"]),
        ]

    def bzsync(self, *args, **kwargs):
        """
        Bugzilla sync of the AffectCVSS instance
        """
        self.save()
        # AffectCVSS needs to be synced through affect
        self.affect.save(*args, **kwargs)

    def sync_to_trackers(self, jira_token):
        """Sync this CVSS in the related Jira tracker."""
        from osidb.models.tracker import Tracker

        if self.affect.is_community:
            return

        tracker = self.affect.tracker
        if (
            tracker
            and not tracker.is_closed
            and tracker.type == Tracker.TrackerType.JIRA
        ):
            # default save already sync with Jira when needed
            tracker.save(jira_token=jira_token)


# List of all states an Affect is considered open/not resolved
AFFECTEDNESS_UNRESOLVED_RESOLUTIONS = {
    Affect.AffectAffectedness.NEW: [
        Affect.AffectResolution.NOVALUE,
    ],
    Affect.AffectAffectedness.AFFECTED: [
        Affect.AffectResolution.DELEGATED,
    ],
}

AFFECTEDNESS_VALID_RESOLUTIONS = {
    Affect.AffectAffectedness.NEW: [
        Affect.AffectResolution.NOVALUE,
        Affect.AffectResolution.DEFER,
        Affect.AffectResolution.WONTFIX,
        Affect.AffectResolution.OOSS,
    ],
    Affect.AffectAffectedness.AFFECTED: [
        Affect.AffectResolution.DELEGATED,
        Affect.AffectResolution.DEFER,
        Affect.AffectResolution.WONTFIX,
        Affect.AffectResolution.OOSS,
    ],
    Affect.AffectAffectedness.NOTAFFECTED: [
        Affect.AffectResolution.NOVALUE,
    ],
    Affect.AffectAffectedness.NOVALUE: [],
}

# Historical affectedness/resolution combinations that were valid in the past
AFFECTEDNESS_HISTORICAL_VALID_RESOLUTIONS = {
    Affect.AffectAffectedness.NEW: [],
    Affect.AffectAffectedness.AFFECTED: [
        Affect.AffectResolution.FIX,
        Affect.AffectResolution.WONTREPORT,
    ],
    Affect.AffectAffectedness.NOTAFFECTED: [],
    Affect.AffectAffectedness.NOVALUE: [
        Affect.AffectResolution.DEFER,
        Affect.AffectResolution.WONTFIX,
    ],
}
