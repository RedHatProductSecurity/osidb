import json
from datetime import timedelta

from celery.exceptions import Ignore
from celery.utils.log import get_task_logger
from django.conf import settings
from django.db import models, transaction
from django.utils import timezone

from config.celery import app
from osidb.core import set_user_acls

logger = get_task_logger(__name__)


class SyncManager(models.Model):
    """
    Abstract model to handle synchronization of some OSIDB data with external system like Bugzilla
    or Jira. Its purpose is to handle scheduling Celery tasks, storing meta-data about when those
    tasks were processed, and re-scheduling tasks when necessary.
    """

    MAX_CONSECUTIVE_FAILURES = 5
    MAX_SCHEDULE_DELAY = timedelta(hours=24)
    MAX_RUN_LENGTH = timedelta(hours=1)
    FAIL_RESCHEDULE_DELAY = timedelta(minutes=5)

    sync_id = models.CharField(max_length=100)
    last_scheduled_dt = models.DateTimeField(blank=True, null=True)
    last_started_dt = models.DateTimeField(blank=True, null=True)
    last_finished_dt = models.DateTimeField(blank=True, null=True)
    last_failed_dt = models.DateTimeField(blank=True, null=True)
    last_failed_reason = models.TextField(blank=True, null=True)  # noqa: DJ01
    last_consecutive_failures = models.IntegerField(default=0)
    permanently_failed = models.BooleanField(default=False)
    last_rescheduled_dt = models.DateTimeField(blank=True, null=True)
    last_rescheduled_reason = models.TextField(blank=True, null=True)  # noqa: DJ01
    last_consecutive_reschedules = models.IntegerField(default=0)

    class Meta:
        abstract = True

    @staticmethod
    def sync_task():
        """
        Override this method with a Celery task to perform external data synchronization.
        """
        raise NotImplementedError("Sync task not implemented.")

    def update_synced_links(self):
        """
        Override this task to update links from updated models to this sync manager.
        """
        raise NotImplementedError("Update synced links not implemented.")

    def schedule(self):
        """
        Schedule sync_task to Celery queue.
        """
        with transaction.atomic():
            self.refresh_from_db()
            self.last_scheduled_dt = timezone.now()
            self.save()
        try:
            self.sync_task.apply_async(args=[self.sync_id])
        except AttributeError:
            raise NotImplementedError(
                "Sync task not implemented or not implemented as Celery task."
            )
        logger.info(f"{self.__class__.__name__} {self.sync_id}: Sync scheduled")

    def started(self, celery_task):
        """
        This method has to be called at the beginning of the sync_task.

        :param celery_task: Associated Celery task.
        """
        with transaction.atomic():
            self.refresh_from_db()

            # Check if task should really run, maybe it was scheduled more times
            # and already executed? In that case revoke it.
            if (
                self.last_started_dt is not None
                and self.last_started_dt >= self.last_scheduled_dt
            ):
                self.revoke_sync_task(celery_task)

            self.last_started_dt = timezone.now()
            self.save()
        logger.info(f"{self.__class__.__name__} {self.sync_id}: Sync started")

    def finished(self):
        """
        This method has to be called when sync_task finishes successfully.
        """
        self.update_synced_links()
        with transaction.atomic():
            self.refresh_from_db()
            self.last_finished_dt = timezone.now()
            self.last_consecutive_failures = 0
            self.last_consecutive_reschedules = 0
            self.permanently_failed = False
            self.save()
        logger.info(
            f"{self.__class__.__name__} {self.sync_id}: Sync finished successfully"
        )

    def failed(self, exception, permanent=False):
        """
        This method has to be called when sync_task fails.

        :param exception: Exception which caused the failure.
        :param permanent: Set to True if problem cannot be solved by running sync_task later.
        """
        self.update_synced_links()
        with transaction.atomic():
            self.refresh_from_db()
            self.last_failed_dt = timezone.now()
            self.last_failed_reason = str(exception).strip()
            self.last_consecutive_failures += 1
            self.last_consecutive_reschedules = 0
            if (
                self.last_consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES
                or permanent
            ):
                self.permanently_failed = True
            self.save()
        logger.info(f"{self.__class__.__name__} {self.sync_id}: Sync failed")
        if self.permanently_failed:
            logger.info(f"{self.__class__.__name__} {self.sync_id}: Sync permanently")
        raise exception

    def revoke_sync_task(self, celery_task):
        """
        Revoke sync_task.

        :param celery_task: Associated Celery task.
        """
        self.update_synced_links()

        celery_task.send_event("task-revoked")
        logger.info(f"{self.__class__.__name__} {self.sync_id}: Revoked")
        raise Ignore

    def reschedule(self, reason):
        """
        Schedule sync_task to Celery queue again for a reason.

        :param reason: Description for a reason why the sync_task was re-scheduled.
        """
        self.schedule()
        with transaction.atomic():
            self.refresh_from_db()
            self.last_rescheduled_dt = timezone.now()
            self.last_rescheduled_reason = reason
            self.last_consecutive_reschedules += 1
            self.save()
        logger.info(
            f"{self.__class__.__name__} {self.sync_id}: Sync re-scheduled ({reason})"
        )

    @classmethod
    def get_sync_manager(cls, sync_id):
        """
        Returns sync manager object for a specific synchronized object ID.

        :param sync_id: Unique ID for synchronized data object.
        """
        result, _ = cls.objects.get_or_create(sync_id=sync_id)
        return result

    @classmethod
    def check_for_reschedules(cls):
        """
        This method needs to be called occasionally to check if any of the existing sync managers
        need to re-schedule tasks for any reason (like previous failure).
        """
        for sync_manager in cls.objects.all():

            # SCHEDULED, DID NOT START
            # 1) Scheduled at least once before
            # 2) Scheduled for more than MAX_SCHEDULE_DELAY
            # 3) Not started after scheduled (or ever)
            #
            #      |       MAX_SCHEDULE_DELAY      |
            #      |-------------------------------|---//-------?
            #  Scheduled                          NOW        Started
            #
            if (
                sync_manager.last_scheduled_dt is not None
                and timezone.now() - sync_manager.last_scheduled_dt
                > cls.MAX_SCHEDULE_DELAY
                and (
                    sync_manager.last_started_dt is None
                    or sync_manager.last_started_dt < sync_manager.last_scheduled_dt
                )
            ):
                sync_manager.reschedule("Sync did not start after MAX_SCHEDULE_DELAY")
                continue

            # STARTED, DID NOT FINISH
            # 1) Started at least once before
            # 2) Running for more than MAX_RUN_LENGTH
            # 3) Not finish after it started (or ever)
            # 4) Not failed after it started (or ever)
            # 5) Not scheduled after started
            #
            #     |       MAX_RUN_LENGTH          |
            #     |-------------------------------|---//-------------?----------------?
            #  Started                           NOW         Success / Failure     Scheduled
            #

            if (
                sync_manager.last_started_dt is not None
                and timezone.now() - sync_manager.last_started_dt > cls.MAX_RUN_LENGTH
                and (
                    sync_manager.last_finished_dt is None
                    or sync_manager.last_finished_dt < sync_manager.last_started_dt
                )
                and (
                    sync_manager.last_failed_dt is None
                    or sync_manager.last_failed_dt < sync_manager.last_started_dt
                )
                and sync_manager.last_scheduled_dt < sync_manager.last_started_dt
            ):
                sync_manager.reschedule("Sync did not finish after MAX_RUN_LENGTH")
                continue

            # STARTED, FAILED, NOT PERMANENTLY
            # 1) Started at least once before
            # 2) Failed recently
            # 3) Not permanent failure
            # 3) Failed more than FAIL_RESCHEDULE_DELAY ago
            # 4) Was not scheduled after last failure
            #
            #                 |     FAIL_RESCHEDULE_DELAY    |
            #     |-----------|------------------------------|---//----------?
            #  Started      Fail (not permanent?)           NOW          Scheduled
            #

            if (
                sync_manager.last_started_dt is not None
                and 0 < sync_manager.last_consecutive_failures
                and not sync_manager.permanently_failed
                and timezone.now() - sync_manager.last_failed_dt
                > cls.FAIL_RESCHEDULE_DELAY
                and sync_manager.last_scheduled_dt < sync_manager.last_failed_dt
            ):
                sync_manager.reschedule(
                    f"Failed {sync_manager.last_consecutive_failures} times"
                )
                continue

    def __str__(self):
        self.refresh_from_db()
        result = ""
        result += f"Sync ID: {self.sync_id}\n"
        result += f"Scheduled: {self.last_scheduled_dt}\n"
        result += f"Started: {self.last_started_dt}\n"
        result += f"Finished: {self.last_finished_dt}\n"
        result += f"Failed: {self.last_failed_dt}\n"
        result += f"Failed consecutive: {self.last_consecutive_failures}\n"
        result += f"Failed reason: {self.last_failed_reason}\n"
        result += f"Rescheduled: {self.last_rescheduled_dt}\n"
        result += f"Rescheduled consecutive: {self.last_consecutive_reschedules}\n"
        result += f"Rescheduled reason: {self.last_rescheduled_reason}\n"
        return result


class FlawDownloadManager(SyncManager):
    """
    Sync manager class for Bugzilla => OSIDB Flaw synchronization.
    """

    @staticmethod
    @app.task(name="sync_manager.flaw_download", bind=True)
    def sync_task(self, flaw_id):
        from collectors.bzimport import collectors

        download = FlawDownloadManager.get_sync_manager(flaw_id)
        download.started(self)

        set_user_acls(settings.ALL_GROUPS)

        # Code adapted from collectors.bzimport.collectors.FlawCollector.collect
        collector = collectors.FlawCollector()
        try:
            collector.sync_flaw(flaw_id)
        except Exception as e:
            download.failed(e)
        else:
            download.finished()
        finally:
            collector.free_queriers()

    def update_synced_links(self):
        from osidb.models import Flaw

        flaws = Flaw.objects.filter(meta_attr__bz_id=self.sync_id)
        flaws.update(download_manager=self)

    def __str__(self):
        from osidb.models import Flaw

        result = super().__str__()

        flaws = Flaw.objects.filter(meta_attr__bz_id=self.sync_id)
        cves = [f.cve_id for f in flaws]
        result += f"Flaws: {cves}\n"

        return result


class BZTrackerDownloadManager(SyncManager):
    """
    Sync manager class for Bugzilla => OSIDB Tracker synchronization.
    """

    @staticmethod
    @app.task(name="sync_manager.bz_tracker_download", bind=True)
    def sync_task(self, tracker_id):
        from collectors.bzimport import collectors

        download = BZTrackerDownloadManager.get_sync_manager(tracker_id)
        download.started(self)

        set_user_acls(settings.ALL_GROUPS)

        # Code adapted from collectors.bzimport.collectors.BugzillaTrackerCollector.collect
        collector = collectors.BugzillaTrackerCollector()
        try:
            collector.sync_tracker(tracker_id)

            # Schedule linking tracker => affect
            link_manager = BZTrackerLinkManager.get_sync_manager(tracker_id)
            link_manager.schedule()
        except Exception as e:
            download.failed(e)
        else:
            download.finished()
        finally:
            collector.free_queriers()

    def update_synced_links(self):
        from osidb.models import Tracker

        trackers = Tracker.objects.filter(external_system_id=self.sync_id)
        trackers.update(download_manager=self)

    def __str__(self):
        from osidb.models import Tracker

        result = super().__str__()

        trackers = Tracker.objects.filter(external_system_id=self.sync_id)
        tracker_ids = [t.external_system_id for t in trackers]
        result += f"Bugzilla trackers: {tracker_ids}\n"

        return result


class BZTrackerLinkManager(SyncManager):
    """
    Sync manager class for Bugzilla => OSIDB Tracker synchronization where only links between
    Tracker and Affects are updated.
    """

    @staticmethod
    @app.task(name="sync_manager.bz_tracker_link", bind=True)
    def sync_task(self, tracker_id):
        from osidb.models import Affect, Flaw, Tracker

        linker = BZTrackerLinkManager.get_sync_manager(tracker_id)
        linker.started(self)

        set_user_acls(settings.ALL_GROUPS)

        # Code adapted from collectors.bzimport.convertors.BugzillaTrackerConvertor.affects
        try:
            tracker = Tracker.objects.get(external_system_id=tracker_id)

            affects = []
            failed_flaws = []
            failed_affects = []

            # Bugzilla flaws
            for bz_id in json.loads(tracker.meta_attr["blocks"]):
                flaws = Flaw.objects.filter(meta_attr__bz_id=str(bz_id))
                if not flaws:
                    failed_flaws.append(bz_id)
                for flaw in flaws:
                    try:
                        affect = flaw.affects.get(
                            ps_module=tracker.meta_attr["ps_module"],
                            ps_component=tracker.meta_attr["ps_component"],
                        )
                    except Affect.DoesNotExist:
                        failed_affects.append(
                            (
                                bz_id,
                                tracker.meta_attr["ps_module"],
                                tracker.meta_attr["ps_component"],
                            )
                        )
                    else:
                        affects.append(affect)

            # Check whiteboard
            process_whiteboard = True
            try:
                whiteboard = json.loads(tracker.meta_attr["whiteboard"])
            except json.JSONDecodeError:
                process_whiteboard = False
            else:
                if not isinstance(whiteboard, dict) or "flaws" not in whiteboard:
                    process_whiteboard = False

            # Non-Bugzilla flaws
            if process_whiteboard:
                for flaw_uuid in whiteboard["flaws"]:
                    try:
                        flaw = Flaw.objects.get(uuid=flaw_uuid)
                    except Flaw.DoesNotExist:
                        # no such flaw
                        continue

                    try:
                        affect = flaw.affects.get(
                            ps_module=tracker.meta_attr["ps_module"],
                            ps_component=tracker.meta_attr["ps_component"],
                        )
                    except Affect.DoesNotExist:
                        # tracker created against
                        # non-existing affect
                        failed_affects.append(
                            (
                                flaw_uuid,
                                tracker.meta_attr["ps_module"],
                                tracker.meta_attr["ps_component"],
                            )
                        )
                        continue

                    affects.append(affect)

            # Prevent eventual duplicates
            affects = list(set(affects))

            with transaction.atomic():
                tracker.affects.clear()
                tracker.affects.add(*affects)
        except Exception as e:
            linker.failed(e)
        else:
            # Handle link failures
            if failed_flaws:
                linker.failed(
                    RuntimeError(
                        f"Flaws do not exist: {failed_flaws}, "
                        f"Affects do not exist: {failed_affects}"
                    )
                )
            elif failed_affects:
                linker.failed(
                    RuntimeError(f"Affects do not exist: {failed_affects}"),
                    permanent=True,
                )
            elif not affects:
                linker.failed(RuntimeError("No Affects found"))
            else:
                linker.finished()

    def update_synced_links(self):
        from osidb.models import Tracker

        trackers = Tracker.objects.filter(external_system_id=self.sync_id)
        trackers.update(bz_link_manager=self)

    def __str__(self):
        from osidb.models import Affect

        result = super().__str__()

        affects = Affect.objects.filter(trackers__external_system_id=self.sync_id)
        affect_strings = [
            f"{a.flaw.bz_id}|{a.ps_module}|{a.ps_component}" for a in affects
        ]
        result += f"Affects: {affect_strings}\n"

        return result


class JiraTrackerLinkManager(SyncManager):
    """
    Sync manager class for Jira => OSIDB Tracker synchronization where only links between
    Tracker and Affects are updated.
    """

    @staticmethod
    @app.task(name="sync_manager.jira_tracker_link", bind=True)
    def sync_task(self, tracker_id):
        from collectors.jiraffe.constants import JIRA_BZ_ID_LABEL_RE
        from osidb.models import Affect, Flaw, Tracker
        from osidb.validators import CVE_RE_STR

        linker = JiraTrackerLinkManager.get_sync_manager(tracker_id)
        linker.started(self)

        set_user_acls(settings.ALL_GROUPS)

        # Code adapted from collectors.jiraffe.convertors.JiraTrackerConvertor.affects
        try:
            tracker = Tracker.objects.get(external_system_id=tracker_id)

            failed_flaws = []
            failed_affects = []

            flaws = set()

            # 1) linking from the flaw side
            for flaw in Flaw.objects.filter(
                meta_attr__jira_trackers__contains=tracker_id
            ):
                # we need to double check the tracker ID
                # as eg. OSIDB-123 is contained in OSIDB-1234
                for item in json.loads(flaw.meta_attr["jira_trackers"]):
                    if tracker_id == item["key"]:
                        flaws.add(flaw)

            # 2) linking from the tracker side
            for label in tracker.meta_attr["labels"]:
                if CVE_RE_STR.match(label):
                    try:
                        flaws.add(Flaw.objects.get(cve_id=label))
                    except Flaw.DoesNotExist:
                        failed_flaws.append(label)
                        continue

                if match := JIRA_BZ_ID_LABEL_RE.match(label):
                    if not (
                        linked_flaws := Flaw.objects.filter(
                            meta_attr__bz_id=match.group(1)
                        )
                    ):
                        # tracker created against
                        # non-existing BZ ID
                        failed_flaws.append(match.group(1))
                        continue

                    flaws.update(linked_flaws)

            affects = []
            for flaw in flaws:
                try:
                    affect = flaw.affects.get(
                        ps_module=tracker.meta_attr["ps_module"],
                        ps_component=tracker.meta_attr["ps_component"],
                    )
                except Affect.DoesNotExist:
                    # tracker created against
                    # non-existing affect
                    failed_affects.append(
                        (
                            flaw.bz_id,
                            tracker.meta_attr["ps_module"],
                            tracker.meta_attr["ps_component"],
                        )
                    )
                    continue

                affects.append(affect)

            with transaction.atomic():
                tracker.affects.clear()
                tracker.affects.add(*affects)
        except Exception as e:
            linker.failed(e)
        else:
            # Handle link failures
            if failed_flaws:
                linker.failed(
                    RuntimeError(
                        f"Flaws do not exist: {failed_flaws}, Affects do not exist: {failed_affects}"
                    )
                )
            elif failed_affects:
                linker.failed(
                    RuntimeError(f"Affects do not exist: {failed_affects}"),
                    permanent=True,
                )
            elif not affects:
                linker.failed(RuntimeError("No Affects found"))
            else:
                linker.finished()

    def update_synced_links(self):
        from osidb.models import Tracker

        trackers = Tracker.objects.filter(external_system_id=self.sync_id)
        trackers.update(jira_link_manager=self)

    def __str__(self):
        from osidb.models import Affect

        result = super().__str__()

        affects = Affect.objects.filter(trackers__external_system_id=self.sync_id)
        affect_strings = [
            f"{a.flaw.bz_id}|{a.ps_module}|{a.ps_component}" for a in affects
        ]
        result += f"Affects: {affect_strings}\n"

        return result
