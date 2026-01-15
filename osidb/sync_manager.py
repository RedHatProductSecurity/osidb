import json
from datetime import timedelta
from typing import Optional, Type

from celery.exceptions import Ignore
from celery.utils.log import get_task_logger
from django.conf import settings
from django.db import models, transaction
from django.utils import timezone
from rhubarb.tasks import LockableTaskWithArgs

from config.celery import app
from osidb.core import set_user_acls

logger = get_task_logger(__name__)


def _sync_jira_trackers(flaw):
    """
    Sync Jira trackers for a flaw with updated Bugzilla information.
    Primarily used to add the flaw:bz# label to the Jira trackers.

    Preconditions (validated by caller):
    - Jira sync is enabled (SYNC_TO_JIRA and JIRA_TOKEN are set)
    - Flaw has a bz_id

    Returns:
        tuple: (successful_updates, failed_updates)
    """

    from collectors.jiraffe.constants import JIRA_TOKEN
    from osidb.models.tracker import Tracker

    successful = 0
    failed = 0

    trackers = (
        Tracker.objects.filter(
            affects__flaw=flaw,
            type=Tracker.TrackerType.JIRA,
        )
        .exclude(external_system_id="")
        .distinct()
    )

    if not trackers.exists():
        return successful, failed

    for tracker in trackers:
        try:
            tracker.save(jira_token=JIRA_TOKEN, raise_validation_error=False)
            successful += 1
        except Exception as e:
            failed += 1
            logger.error(
                f"Failed to update Jira tracker {tracker.external_system_id} for flaw {flaw.uuid}: {e}",
                extra={
                    "flaw_uuid": str(flaw.uuid),
                    "bz_id": flaw.bz_id,
                    "tracker_external_system_id": tracker.external_system_id,
                },
                exc_info=True,
            )

    return successful, failed


class SyncManager(models.Model):
    """
    Abstract model to handle synchronization of some OSIDB data with external system like Bugzilla
    or Jira. Its purpose is to handle scheduling Celery tasks, storing meta-data about when those
    tasks were processed, and re-scheduling tasks when necessary.

    The philosophy:
    - Provide visibility (when and how many times a task ran or failed, why it failed).
    - Straightforward (short implementation, easy to understand, errors not obscured
                       or masked by complicated logic).
    - Queue in order (SyncManager tries to send tasks to Celery without reordering,
                      which happens only on retries).
    - The queued tasks should be idempotent or close to idempotent
        (it shouldn't matter if a task fails or if it runs multiple times, the end
         result should be the same in the end).
    """

    class SyncManagerMode:
        """
        SyncManager modes:
        - DEFAULT: No special handling.
        - EXCLUSIVE: Only one task can run at a time. If a task is already running,
          the new task will be scheduled with a countdown
        """

        DEFAULT = 0
        EXCLUSIVE = 1

    MAX_CONSECUTIVE_FAILURES = 5
    MAX_SCHEDULE_DELAY = timedelta(hours=24)
    MAX_RUN_LENGTH = timedelta(hours=1)
    FAIL_RESCHEDULE_DELAY = timedelta(minutes=5)
    MODE = SyncManagerMode.DEFAULT
    COUNTDOWN = 60  # Default countdown for exclusive mode

    sync_id = models.CharField(max_length=100, unique=True)
    last_scheduled_dt = models.DateTimeField(blank=True, null=True)
    last_started_dt = models.DateTimeField(blank=True, null=True)
    last_finished_dt = models.DateTimeField(blank=True, null=True)
    last_failed_dt = models.DateTimeField(blank=True, null=True)
    last_failed_reason = models.TextField(blank=True, null=True)  # noqa: DJ001
    last_consecutive_failures = models.IntegerField(default=0)
    permanently_failed = models.BooleanField(default=False)
    last_rescheduled_dt = models.DateTimeField(blank=True, null=True)
    last_rescheduled_reason = models.TextField(blank=True, null=True)  # noqa: DJ001
    last_consecutive_reschedules = models.IntegerField(default=0)

    class Meta:
        abstract = True

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

    @staticmethod
    def sync_task(*args, **kwargs):
        """
        Override this method with a Celery task to perform external data synchronization.
        """
        raise NotImplementedError("Sync task not implemented.")

    def update_synced_links(self):
        """
        Override this task to update links from updated models to this sync manager.
        """
        raise NotImplementedError("Update synced links not implemented.")

    @classmethod
    def check_conflicting_sync_managers(
        cls, sync_id, celery_task, related_managers: list[Type["SyncManager"]]
    ):
        """
        Override this method to check for conflicting sync managers.
        """
        raise NotImplementedError("Conflicting sync managers check not implemented.")

    @classmethod
    def schedule(cls, sync_id, *args, schedule_options=None, **kwargs):
        """
        Schedule sync_task to Celery queue.

        :param sync_id: Unique ID for synchronized data object.
        :param schedule_options: Dictionary of options to pass to apply_async
        """

        if schedule_options is None:
            schedule_options = {}

        created = cls.objects.get_or_create(sync_id=sync_id)[1]
        cls.objects.filter(sync_id=sync_id).update(last_scheduled_dt=timezone.now())

        if not created and cls.MODE == cls.SyncManagerMode.EXCLUSIVE:
            # Check if the task needs to be rescheduled
            if not cls.is_scheduled(sync_id):
                logger.info(
                    f"{cls.__name__} {sync_id}: Task already in progress"
                    f", postponing for {schedule_options.get('countdown', cls.COUNTDOWN)} seconds"
                )
                if "countdown" not in schedule_options:
                    schedule_options["countdown"] = cls.COUNTDOWN
                cls.reschedule(
                    sync_id,
                    "Task already in progress",
                    schedule_options=schedule_options,
                )
                return

        # Create model linkage if possible to make checking for conflicting
        # sync managers possible
        manager = cls.objects.get(sync_id=sync_id)
        manager.update_synced_links()

        def schedule_task():
            try:
                cls.sync_task.apply_async(
                    args=[sync_id, *args],
                    kwargs=kwargs | {"object_id": sync_id},
                    **schedule_options,
                )
            except AttributeError:
                raise NotImplementedError(
                    "Sync task not implemented or not implemented as Celery task."
                )
            logger.info(f"{cls.__name__} {sync_id}: Sync scheduled")

        # Avoid race condition by ensuring the task is scheduled after the
        # transaction so that the manager instance actually exists
        transaction.on_commit(schedule_task)

    @classmethod
    def started(
        cls,
        sync_id,
        celery_task,
        related_managers: Optional[list[Type["SyncManager"]]] = None,
    ):
        """
        This method has to be called at the beginning of the sync_task.

        :param sync_id: Unique ID for synchronized data object.
        :param celery_task: Associated Celery task.
        :param related_managers: Optional related managers which should be checked for conflicts
        """

        if related_managers is None:
            related_managers = []

        try:
            cls.check_conflicting_sync_managers(sync_id, celery_task, related_managers)
        except NotImplementedError:
            logger.info(
                f"{cls.__name__} {sync_id}: "
                "Conflicting sync managers check not implemented"
            )

        manager = cls.objects.get(sync_id=sync_id)

        # Check if task should really run, maybe it was scheduled more times
        # and already executed? In that case revoke it.
        if (
            manager.last_started_dt is not None
            and manager.last_started_dt >= manager.last_scheduled_dt
        ):
            manager.revoke_sync_task(celery_task)

        cls.objects.filter(sync_id=sync_id).update(last_started_dt=timezone.now())
        logger.info(f"{cls.__name__} {sync_id}: Sync started")

    @classmethod
    def finished(cls, sync_id):
        """
        This method has to be called when sync_task finishes successfully.

        :param sync_id: Unique ID for synchronized data object.
        """
        manager = cls.objects.get(sync_id=sync_id)
        manager.update_synced_links()

        cls.objects.filter(sync_id=sync_id).update(
            last_finished_dt=timezone.now(),
            last_consecutive_failures=0,
            last_consecutive_reschedules=0,
            permanently_failed=False,
        )
        logger.info(f"{cls.__name__} {sync_id}: Sync finished successfully")

    @classmethod
    def failed(cls, sync_id, exception, permanent=False):
        """
        This method has to be called when sync_task fails.

        :param sync_id: Unique ID for synchronized data object.
        :param exception: Exception which caused the failure.
        :param permanent: Set to True if problem cannot be solved by running sync_task later.
        """
        manager = cls.objects.get(sync_id=sync_id)
        manager.update_synced_links()

        updated_last_consecutive_failures = manager.last_consecutive_failures + 1
        updated_permanently_failed = False
        if (
            manager.last_consecutive_failures >= manager.MAX_CONSECUTIVE_FAILURES
            or permanent
        ):
            updated_permanently_failed = True

        cls.objects.filter(sync_id=sync_id).update(
            last_failed_dt=timezone.now(),
            last_failed_reason=str(exception).strip(),
            last_consecutive_failures=updated_last_consecutive_failures,
            last_consecutive_reschedules=0,
            permanently_failed=updated_permanently_failed,
        )
        logger.info(f"{cls.__name__} {sync_id}: Sync failed")
        if updated_permanently_failed:
            logger.info(f"{cls.__name__} {sync_id}: Sync failed permanently")
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

    @classmethod
    def reschedule(cls, sync_id, reason, *args, **kwargs):
        """
        Schedule sync_task to Celery queue again for a reason.

        :param sync_id: Unique ID for synchronized data object.
        :param reason: Description for a reason why the sync_task was re-scheduled.
        :param schedule_options: Dictionary of options to pass to apply_async
        """

        manager = cls.objects.get(sync_id=sync_id)
        updated_last_consecutive_reschedules = manager.last_consecutive_reschedules + 1

        cls.objects.filter(sync_id=sync_id).update(
            last_rescheduled_dt=timezone.now(),
            last_rescheduled_reason=reason,
            last_consecutive_reschedules=updated_last_consecutive_reschedules,
        )
        cls.schedule(sync_id, *args, **kwargs)
        logger.info(f"{cls.__name__} {sync_id}: Sync re-scheduled ({reason})")

    @classmethod
    def check_for_reschedules(cls):
        """
        This method needs to be called occasionally to check if any of the existing sync managers
        need to re-schedule tasks for any reason (like previous failure).
        """
        for sync_manager in cls.objects.all():
            # TODO: Find a cause and remove this workaround OSIDB-3131
            # TODO: Should be fixed, check from time to time to see if this problem is logged
            if (
                sync_manager.last_scheduled_dt is None
                and sync_manager.last_started_dt is not None
            ):
                logger.info(
                    f"{sync_manager.__class__.__name__} {sync_manager.sync_id}: "
                    f"Started but not scheduled, this should NEVER happen"
                )
                continue

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
                cls.reschedule(
                    sync_manager.sync_id, "Sync did not start after MAX_SCHEDULE_DELAY"
                )
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
                cls.reschedule(
                    sync_manager.sync_id, "Sync did not finish after MAX_RUN_LENGTH"
                )
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
                cls.reschedule(
                    sync_manager.sync_id,
                    f"Failed {sync_manager.last_consecutive_failures} times",
                )
                continue

    @classmethod
    def is_in_progress(cls, sync_id):
        """
        Return True if the task is still considered in-progress:
        1) It has a start timestamp,
        2) It has not finished or failed since that start, and
        3) It hasn’t exceeded MAX_RUN_LENGTH (to catch crashed/hung tasks).
        """
        now = timezone.now()
        manager = cls.objects.get(sync_id=sync_id)

        # 1) Must have started
        if manager.last_started_dt is None:
            return False

        # 2) Must not have finished or failed since that start
        if (
            manager.last_failed_dt is not None
            and manager.last_failed_dt > manager.last_started_dt
        ) or (
            manager.last_finished_dt is not None
            and manager.last_finished_dt > manager.last_started_dt
        ):
            return False

        # 3) Must be within the allowed run length window
        if now - manager.last_started_dt > cls.MAX_RUN_LENGTH:
            # Timed out: assume crash/hang and treat as not running
            return False

        return True

    @classmethod
    def is_scheduled(cls, sync_id):
        """
        Returns True if there is a scheduled-but-not-yet-started run, in either:

        1) A running task that was deferred (rescheduled), or
        2) An idle task that has a fresh schedule after its last completion.
        """

        manager = cls.objects.get(sync_id=sync_id)

        if cls.is_in_progress(sync_id):
            # During a run, last_rescheduled_dt is set when we defer for retry.
            # But it persists across runs, so only count it if it’s
            # newer than the current start (i.e. a fresh defer).
            return (
                manager.last_rescheduled_dt is not None
                and manager.last_rescheduled_dt > manager.last_started_dt
            )

        # Not running: use last_scheduled_dt, but only if it was set
        # after the most recent finish (or at all if never run).
        return (
            manager.last_scheduled_dt is not None
            and (
                manager.last_finished_dt is None
                or manager.last_scheduled_dt > manager.last_finished_dt
            )
            or (
                manager.last_rescheduled_dt is not None
                and manager.last_consecutive_reschedules > 0
                and manager.permanently_failed is False
            )
        )


class BZTrackerDownloadManager(SyncManager):
    """
    Sync manager class for Bugzilla => OSIDB Tracker synchronization.
    """

    def __str__(self):
        from osidb.models import Tracker

        result = super().__str__()

        trackers = Tracker.objects.filter(external_system_id=self.sync_id)
        tracker_ids = [t.external_system_id for t in trackers]
        result += f"Bugzilla trackers: {tracker_ids}\n"

        return result

    @staticmethod
    def link_tracker_with_affects(tracker_id):
        # Code adapted from collectors.bzimport.convertors.BugzillaTrackerConvertor.affects

        from osidb.models import Affect, Flaw, Tracker

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
                        ps_update_stream=tracker.ps_update_stream,
                        ps_component=tracker.meta_attr["ps_component"],
                    )
                except Affect.DoesNotExist:
                    failed_affects.append(
                        (
                            bz_id,
                            tracker.ps_update_stream,
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
                        ps_update_stream=tracker.ps_update_stream,
                        ps_component=tracker.meta_attr["ps_component"],
                    )
                except Affect.DoesNotExist:
                    # tracker created against
                    # non-existing affect
                    failed_affects.append(
                        (
                            flaw_uuid,
                            tracker.ps_update_stream,
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
            tracker.save(raise_validation_error=False, auto_timestamps=False)

        return affects, failed_flaws, failed_affects

    @staticmethod
    @app.task(name="sync_manager.bz_tracker_download", bind=True)
    def sync_task(task, tracker_id, **kwargs):
        from collectors.bzimport import collectors

        BZTrackerDownloadManager.started(tracker_id, task)

        set_user_acls(settings.ALL_GROUPS)

        # Code adapted from collectors.bzimport.collectors.BugzillaTrackerCollector.collect
        collector = collectors.BugzillaTrackerCollector()
        try:
            collector.sync_tracker(tracker_id)
            result = BZTrackerDownloadManager.link_tracker_with_affects(tracker_id)
            # Handle link failures
            affects, failed_flaws, failed_affects = result
            if failed_flaws:
                BZTrackerDownloadManager.failed(
                    tracker_id,
                    RuntimeError(
                        f"Flaws do not exist: {failed_flaws}, "
                        f"Affects do not exist: {failed_affects}"
                    ),
                )
            elif failed_affects:
                BZTrackerDownloadManager.failed(
                    tracker_id,
                    RuntimeError(f"Affects do not exist: {failed_affects}"),
                    permanent=True,
                )
            elif not affects:
                BZTrackerDownloadManager.failed(
                    tracker_id, RuntimeError("No Affects found")
                )
        except Exception as e:
            BZTrackerDownloadManager.failed(tracker_id, e)
        else:
            BZTrackerDownloadManager.finished(tracker_id)
        finally:
            collector.free_queriers()

    def update_synced_links(self):
        from osidb.models import Tracker

        Tracker.objects.filter(external_system_id=self.sync_id).update(
            bz_download_manager=self
        )


class BZSyncManager(SyncManager):
    """
    Sync manager class for OSIDB => Bugzilla synchronization.
    """

    def __str__(self):
        from osidb.models import Flaw

        result = super().__str__()
        flaws = Flaw.objects.filter(uuid=self.sync_id)
        cves = [f.cve_id or f.uuid for f in flaws]
        result += f"Flaws: {cves}\n"

        return result

    @classmethod
    def schedule(cls, sync_id, *args, **kwargs):
        """
        Schedule BZSyncManager's sync_task to Celery queue.

        This implementation uses custom de-duplication logic
        and a 20 seconds delay to mitigate "outdated model" conflicts on bugzilla.
        See OSIDB-3205 for more details.

        :param sync_id: Unique ID for synchronized data object.
        """

        # NOT calling super().schedule() on purpose. If the SyncManager
        # implementation changes, this becomes further technical debt.

        manager, _ = cls.objects.get_or_create(sync_id=sync_id)

        now = timezone.now()

        skip = False

        # Check if task should really run. If it is schedule multiple times
        # within FAIL_RESCHEDULE_DELAY, assume duplicates are attempted to
        # be scheduled. (If after more than FAIL_RESCHEDULE_DELAY,
        # allow reschedules.)
        # ScheduleManager.started is prone to race condition if started in
        # multiple celery workers concurrently, hence this check.
        if (
            manager.last_started_dt is not None
            and manager.last_scheduled_dt is not None
            and manager.last_started_dt < manager.last_scheduled_dt
            and now - manager.last_scheduled_dt < cls.FAIL_RESCHEDULE_DELAY
        ) or (
            manager.last_started_dt is None
            and manager.last_scheduled_dt is not None
            and now - manager.last_scheduled_dt < cls.FAIL_RESCHEDULE_DELAY
        ):
            skip = True

        if skip:
            logger.info(f"{cls.__name__} {sync_id}: Duplicate schedule skipped")
        else:
            cls.objects.filter(sync_id=sync_id).update(last_scheduled_dt=now)

            def schedule_task():
                try:
                    # countdown=20 so that if a client's action consists of a burst of
                    # multiple requests, the executed task probably doesn't start in the middle.
                    cls.sync_task.apply_async(
                        args=[sync_id, *args], kwargs=kwargs, countdown=20
                    )
                except AttributeError:
                    raise NotImplementedError(
                        "Sync task not implemented or not implemented as Celery task."
                    )
                logger.info(f"{cls.__name__} {sync_id}: Sync scheduled")

            # Avoid race condition by ensuring the task is scheduled after the
            # transaction so that the manager instance actually exists
            transaction.on_commit(schedule_task)

    @staticmethod
    @app.task(name="sync_manager.bzsync", bind=True)
    def sync_task(task, flaw_id, **kwargs):
        # flaw_id is the flaw UUID
        from osidb.models import Flaw

        BZSyncManager.started(flaw_id, task)

        set_user_acls(settings.ALL_GROUPS)

        try:
            flaw = Flaw.objects.get(uuid=flaw_id)
            flaw._perform_bzsync()
        except Exception as e:
            BZSyncManager.failed(flaw_id, e)
        else:
            BZSyncManager.finished(flaw_id)

    def update_synced_links(self):
        from osidb.models import Flaw

        Flaw.objects.filter(uuid=self.sync_id).update(bzsync_manager=self)

    @classmethod
    def finished(cls, sync_id):
        from apps.trackers.constants import SYNC_TO_JIRA
        from collectors.jiraffe.constants import JIRA_TOKEN
        from osidb.models import Flaw

        super().finished(sync_id)

        if not SYNC_TO_JIRA or not JIRA_TOKEN:
            return

        # Post-BZ-sync: Sync Jira trackers to make sure that
        # they have the the flaw:bz# label.
        try:
            flaw = Flaw.objects.get(uuid=sync_id)
        except Flaw.DoesNotExist:
            logger.error(f"Post-BZ-sync Jira update for {sync_id}: Flaw not found")
            return

        if not flaw.bz_id:
            logger.debug(f"Post-BZ-sync Jira update for {sync_id}: No bz_id, skipping")
            return

        successful, failed = _sync_jira_trackers(flaw)
        if successful:
            logger.info(
                f"Post-BZ-sync Jira update for {sync_id}: "
                f"Updated {successful} tracker(s) with bz_id label"
            )
        if failed:
            logger.warning(
                f"Post-BZ-sync Jira update for {sync_id}: "
                f"Failed to update {failed} tracker(s)"
            )


class JiraTaskDownloadManager(SyncManager):
    """
    Sync manager class for Jira => OSIDB Task synchronization.
    """

    def __str__(self):
        from osidb.models import Flaw

        result = super().__str__()

        flaws = Flaw.objects.filter(task_key=self.sync_id)
        flaw_ids = [f.cve_id if f.cve_id else f.uuid for f in flaws]
        result += f"Jira tasks for flaws: {flaw_ids}\n"

        return result

    @staticmethod
    @app.task(name="sync_manager.jira_task_download", bind=True)
    def sync_task(task, task_id, **kwargs):
        from collectors.jiraffe.convertors import JiraTaskConvertor
        from collectors.jiraffe.core import JiraQuerier

        set_user_acls(settings.ALL_GROUPS)
        JiraTaskDownloadManager.started(
            task_id,
            task,
            related_managers=[JiraTaskSyncManager, JiraTaskTransitionManager],
        )

        try:
            task_data = JiraQuerier().get_issue(task_id, expand="changelog")
            flaw = JiraTaskConvertor(task_data).flaw
            if flaw:
                flaw.save()
        except Exception as e:
            JiraTaskDownloadManager.failed(task_id, e)
        else:
            JiraTaskDownloadManager.finished(task_id)

    @classmethod
    def check_conflicting_sync_managers(
        cls, sync_id, celery_task, related_managers: list[Type[SyncManager]]
    ):
        from osidb.models import Flaw

        set_user_acls(settings.ALL_GROUPS)
        countdown = 60  # 1 minute
        existing_flaw = Flaw.objects.filter(task_key=sync_id).first()

        if existing_flaw:
            for sync_manager_type in related_managers:
                conflicting_sync_manager = sync_manager_type.objects.filter(
                    sync_id=existing_flaw.uuid
                ).first()

                if conflicting_sync_manager:
                    conflicting_pending_sync = conflicting_sync_manager.is_in_progress(
                        existing_flaw.uuid
                    ) or conflicting_sync_manager.is_scheduled(existing_flaw.uuid)

                    if conflicting_pending_sync:
                        logger.info(
                            f"{cls.__name__} {sync_id}: Conflicting sync managers found "
                            f"({conflicting_sync_manager.__class__.__name__}), postponed for "
                            f"{countdown} seconds."
                        )
                        cls.schedule(sync_id, schedule_options={"countdown": countdown})
                        manager = cls.objects.get(sync_id=sync_id)
                        manager.revoke_sync_task(celery_task)

    def update_synced_links(self):
        from osidb.models import Flaw

        Flaw.objects.filter(task_key=self.sync_id).update(task_download_manager=self)


class JiraTaskSyncManager(SyncManager):
    """
    Sync manager class for OSIDB => Jira Task synchronization.
    """

    def __str__(self):
        from osidb.models import Flaw

        result = super().__str__()
        flaws = Flaw.objects.filter(uuid=self.sync_id)
        cves = [f.cve_id or f.uuid for f in flaws]
        result += f"Flaws: {cves}\n"

        return result

    @staticmethod
    @app.task(name="sync_manager.jira_task_sync", bind=True)
    def sync_task(task, flaw_id, **kwargs):
        """
        perform the sync of the task of the given flaw to Jira

        the task may not be existing yet when performing the first
        sync therefore we use the flaw UUID as the identifier
        """
        from osidb.models import Flaw

        JiraTaskSyncManager.started(flaw_id, task)

        set_user_acls(settings.ALL_GROUPS)

        try:
            flaw = Flaw.objects.get(uuid=flaw_id)
            flaw._create_or_update_task()

        except Exception as e:
            JiraTaskSyncManager.failed(flaw_id, e)
        else:
            JiraTaskSyncManager.finished(flaw_id)

    def update_synced_links(self):
        from osidb.models import Flaw

        Flaw.objects.filter(uuid=self.sync_id).update(task_sync_manager=self)


class JiraTaskTransitionManager(SyncManager):
    """
    Transition manager class for OSIDB => Jira Task state synchronization.
    """

    MODE = SyncManager.SyncManagerMode.EXCLUSIVE

    def __str__(self):
        from osidb.models import Flaw

        result = super().__str__()
        flaws = Flaw.objects.filter(uuid=self.sync_id)
        cves = [f.cve_id or f.uuid for f in flaws]
        result += f"Flaws: {cves}\n"

        return result

    @staticmethod
    @app.task(
        base=LockableTaskWithArgs,
        name="sync_manager.jira_task_transition",
        bind=True,
        lock_ttl=60,
    )
    def sync_task(task, flaw_id, **kwargs):
        """
        perform the sync of the task state of the given flaw to Jira

        the task must exist or otherwise the operation fails
        the flaw UUID is ensured so it is used as the identifier
        """
        from osidb.models import Flaw

        JiraTaskTransitionManager.started(flaw_id, task)

        set_user_acls(settings.ALL_GROUPS)

        try:
            flaw = Flaw.objects.get(uuid=flaw_id)
            flaw._transition_task()

        except Exception as e:
            JiraTaskTransitionManager.failed(flaw_id, e)
        else:
            JiraTaskTransitionManager.finished(flaw_id)

    def update_synced_links(self):
        from osidb.models import Flaw

        Flaw.objects.filter(uuid=self.sync_id).update(task_transition_manager=self)


class JiraTrackerDownloadManager(SyncManager):
    """
    Sync manager class for Jira => OSIDB Tracker synchronization.
    """

    def __str__(self):
        from osidb.models import Tracker

        result = super().__str__()

        trackers = Tracker.objects.filter(external_system_id=self.sync_id)
        tracker_ids = [t.external_system_id for t in trackers]
        result += f"Jira trackers: {tracker_ids}\n"

        return result

    @staticmethod
    def link_tracker_with_affects(tracker_id):
        # Code adapted from collectors.jiraffe.convertors.JiraTrackerConvertor.affects

        from collectors.jiraffe.constants import JIRA_BZ_ID_LABEL_RE
        from osidb.models import Affect, Flaw, Tracker
        from osidb.validators import CVE_RE_STR

        tracker = Tracker.objects.get(external_system_id=tracker_id)

        failed_flaws = []
        failed_affects = []

        flaws = set()

        # 1) linking from the flaw side
        for flaw in Flaw.objects.filter(meta_attr__jira_trackers__contains=tracker_id):
            # we need to double check the tracker ID
            # as eg. OSIDB-123 is contained in OSIDB-1234
            for item in json.loads(flaw.meta_attr["jira_trackers"]):
                if tracker_id == item["key"]:
                    flaws.add(flaw)

        # 2) linking from the tracker side
        for label in json.loads(tracker.meta_attr["labels"]):
            if CVE_RE_STR.match(label):
                try:
                    flaws.add(Flaw.objects.get(cve_id=label))
                except Flaw.DoesNotExist:
                    failed_flaws.append(label)
                    continue

            if label.startswith("flawuuid:"):
                flaw_uuid = label.split(":")[1]
                try:
                    flaws.add(Flaw.objects.get(uuid=flaw_uuid))
                except Flaw.DoesNotExist:
                    failed_flaws.append(flaw_uuid)
                    continue

            if match := JIRA_BZ_ID_LABEL_RE.match(label):
                if not (
                    linked_flaws := Flaw.objects.filter(meta_attr__bz_id=match.group(1))
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
                    ps_update_stream=tracker.ps_update_stream,
                    ps_component=tracker.meta_attr["ps_component"],
                )
            except Affect.DoesNotExist:
                # tracker created against
                # non-existing affect
                failed_affects.append(
                    (
                        flaw.bz_id,
                        tracker.ps_update_stream,
                        tracker.meta_attr["ps_component"],
                    )
                )
                continue

            affects.append(affect)

        with transaction.atomic():
            tracker.affects.clear()
            tracker.affects.add(*affects)
            tracker.save(raise_validation_error=False, auto_timestamps=False)

        return affects, failed_flaws, failed_affects

    @staticmethod
    @app.task(name="sync_manager.jira_tracker_download", bind=True)
    def sync_task(task, tracker_id, **kwargs):
        from collectors.jiraffe.convertors import JiraTrackerConvertor
        from collectors.jiraffe.core import JiraQuerier

        JiraTrackerDownloadManager.started(tracker_id, task)

        set_user_acls(settings.ALL_GROUPS)

        try:
            tracker_data = JiraQuerier().get_issue(tracker_id)
            tracker = JiraTrackerConvertor(tracker_data).tracker
            if tracker:
                tracker.save()
                result = JiraTrackerDownloadManager.link_tracker_with_affects(
                    tracker_id
                )

                # Handle link failures
                affects, failed_flaws, failed_affects = result
                if failed_flaws:
                    JiraTrackerDownloadManager.failed(
                        tracker_id,
                        RuntimeError(
                            f"Flaws do not exist: {failed_flaws}, "
                            f"Affects do not exist: {failed_affects}"
                        ),
                    )
                elif failed_affects:
                    JiraTrackerDownloadManager.failed(
                        tracker_id,
                        RuntimeError(f"Affects do not exist: {failed_affects}"),
                        permanent=True,
                    )
                elif not affects:
                    JiraTrackerDownloadManager.failed(
                        tracker_id, RuntimeError("No Affects found")
                    )
        except Exception as e:
            JiraTrackerDownloadManager.failed(tracker_id, e)
        else:
            JiraTrackerDownloadManager.finished(tracker_id)

    def update_synced_links(self):
        from osidb.models import Tracker

        Tracker.objects.filter(external_system_id=self.sync_id).update(
            jira_download_manager=self
        )
