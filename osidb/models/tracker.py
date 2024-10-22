import logging
import uuid

from django.contrib.postgres.indexes import GinIndex
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import models
from django.db.models import Q
from django.db.utils import IntegrityError
from psqlextra.fields import HStoreField

from apps.bbsync.constants import SYNC_TRACKERS_TO_BZ
from apps.trackers.constants import SYNC_TO_JIRA
from apps.trackers.models import JiraBugIssuetype
from osidb.mixins import (
    ACLMixin,
    ACLMixinManager,
    AlertMixin,
    NullStrFieldsMixin,
    TrackingMixin,
    TrackingMixinManager,
)
from osidb.models.affect import Affect
from osidb.sync_manager import (
    BZTrackerDownloadManager,
    BZTrackerLinkManager,
    JiraTrackerDownloadManager,
    JiraTrackerLinkManager,
)

from .ps_module import PsModule
from .ps_update_stream import PsUpdateStream

logger = logging.getLogger(__name__)


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

    # non operational meta data
    meta_attr = HStoreField(default=dict)

    # An Affect can have many trackers, and a tracker can track multiple flaw/affects
    affects = models.ManyToManyField(Affect, related_name="trackers", blank=True)

    last_impact_increase_dt = models.DateTimeField(null=True, blank=True)

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

        # when validation is required, run before BTS sync
        raise_validation_error = kwargs.get("raise_validation_error", True)
        if raise_validation_error:
            self.validate(dry_run=kwargs.get("no_alerts", False))

        # the validations were already run
        kwargs["raise_validation_error"] = False
        kwargs["no_alerts"] = True

        # check Bugzilla conditions are met
        if (
            SYNC_TRACKERS_TO_BZ
            and bz_api_key is not None
            and self.type == self.TrackerType.BUGZILLA
        ):
            # avoid creating tracker in duplicity
            # from places where skips validations
            if not self.external_system_id:
                self._validate_tracker_duplicate()
            # sync to Bugzilla
            tracker_instance = TrackerSaver(self, bz_api_key=bz_api_key).save()
            # save in case a new Bugzilla ID was obtained
            # so the tracker is later matched in BZ import
            kwargs[
                "auto_timestamps"
            ] = False  # the timestamps will be get from Bugzilla
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
            # avoid creating tracker in duplicity
            # from places where skips validations
            if not self.external_system_id:
                self._validate_tracker_duplicate()
            # sync to Jira
            actual_jira_issuetype = "Vulnerability"
            if JiraBugIssuetype.objects.filter(
                project=PsModule.objects.get(
                    name=self.affects.first().ps_module
                ).bts_key
            ).exists():
                actual_jira_issuetype = "Bug"

            if "jira_issuetype" in self.meta_attr:
                actual_jira_issuetype = self.meta_attr["jira_issuetype"]

            tracker_instance = TrackerSaver(
                self, jira_token=jira_token, jira_issuetype=actual_jira_issuetype
            ).save()
            # save in case a new Jira ID was obtained
            # so the flaw is later matched in Jiraffe sync
            kwargs[
                "auto_timestamps"
            ] = False  # the timestamps will be get from Bugzilla
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
            try:
                super().save(*args, **kwargs)
            except (IntegrityError, ValidationError) as e:
                exc_msg = str(e)
                if (
                    (
                        "duplicate key value violates unique constraint" in exc_msg
                        and "osidb_tracker_type_external_system_id" in exc_msg
                    )
                    or "Constraint “unique_external_system_id” is violated." in exc_msg
                ):
                    # Tracker collector collected this tracker before the whole saving process finished
                    # in the OSIDB, skip the saving and log it
                    warning_msg = (
                        f"{e} occured for tracker with external system id '{self.external_system_id}' and uuid '{self.uuid}',"
                        "skipping the exception as tracker with this external system id was already collected "
                        "by Tracker Collector."
                    )
                    logger.warning(warning_msg)
                else:
                    # Other IntegrityError, reraise the exception
                    raise e

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
        from osidb.models.flaw.flaw import Flaw

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
                "The tracker is associated with a NOTAFFECTED affect: "
                f"{affect.ps_module}/{affect.ps_component} ({affect.uuid})"
            )

    def _validate_ooss_open_tracker(self, **kwargs):
        """
        Check whether out of support scope products have open trackers.
        """
        affect = self.affects.filter(resolution=Affect.AffectResolution.OOSS).first()
        if not self.is_closed and affect:
            raise ValidationError(
                "The tracker is associated with an OOSS affect: "
                f"{affect.ps_module}/{affect.ps_component} ({affect.uuid})"
            )

    def _validate_wontfix_open_tracker(self, **kwargs):
        """
        Check whether wontfix affects have open trackers.
        """
        affect = self.affects.filter(resolution=Affect.AffectResolution.WONTFIX).first()
        if not self.is_closed and affect:
            raise ValidationError(
                "The tracker is associated with a WONTFIX affect: "
                f"{affect.ps_module}/{affect.ps_component} ({affect.uuid})"
            )

    def _validate_defer_open_tracker(self, **kwargs):
        """
        Check whether DEFER affects have open trackers.
        """
        affect = self.affects.filter(resolution=Affect.AffectResolution.DEFER).first()
        if not self.is_closed and affect:
            raise ValidationError(
                "The tracker is associated with a DEFER affect: "
                f"{affect.ps_module}/{affect.ps_component} ({affect.uuid})"
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
                    "is already associated with the affect "
                    f"{affect.ps_module}/{affect.ps_component} ({affect.uuid})"
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

    bz_download_manager = models.ForeignKey(
        BZTrackerDownloadManager, null=True, blank=True, on_delete=models.CASCADE
    )
    bz_link_manager = models.ForeignKey(
        BZTrackerLinkManager, null=True, blank=True, on_delete=models.CASCADE
    )
    jira_download_manager = models.ForeignKey(
        JiraTrackerDownloadManager, null=True, blank=True, on_delete=models.CASCADE
    )
    jira_link_manager = models.ForeignKey(
        JiraTrackerLinkManager, null=True, blank=True, on_delete=models.CASCADE
    )
