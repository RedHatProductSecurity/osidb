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

    MAX_CONSECUTIVE_FAILURES = 5
    MAX_SCHEDULE_DELAY = timedelta(hours=24)
    MAX_RUN_LENGTH = timedelta(hours=1)
    FAIL_RESCHEDULE_DELAY = timedelta(minutes=5)

    sync_id = models.CharField(max_length=100, unique=True)
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

    @classmethod
    def schedule(cls, sync_id, *args, **kwargs):
        """
        Schedule sync_task to Celery queue.

        :param sync_id: Unique ID for synchronized data object.
        """
        cls.objects.get_or_create(sync_id=sync_id)
        cls.objects.filter(sync_id=sync_id).update(last_scheduled_dt=timezone.now())

        def schedule_task():
            try:
                cls.sync_task.apply_async(args=[sync_id, *args], kwargs=kwargs)
            except AttributeError:
                raise NotImplementedError(
                    "Sync task not implemented or not implemented as Celery task."
                )
            logger.info(f"{cls.__name__} {sync_id}: Sync scheduled")

        # Avoid race condition by ensuring the task is scheduled after the
        # transaction so that the manager instance actually exists
        transaction.on_commit(schedule_task)

    @classmethod
    def started(cls, sync_id, celery_task):
        """
        This method has to be called at the beginning of the sync_task.

        :param sync_id: Unique ID for synchronized data object.
        :param celery_task: Associated Celery task.
        """
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
    def reschedule(cls, sync_id, reason):
        """
        Schedule sync_task to Celery queue again for a reason.

        :param sync_id: Unique ID for synchronized data object.
        :param reason: Description for a reason why the sync_task was re-scheduled.
        """
        cls.schedule(sync_id)

        manager = cls.objects.get(sync_id=sync_id)
        updated_last_consecutive_reschedules = manager.last_consecutive_reschedules + 1

        cls.objects.filter(sync_id=sync_id).update(
            last_rescheduled_dt=timezone.now(),
            last_rescheduled_reason=reason,
            last_consecutive_reschedules=updated_last_consecutive_reschedules,
        )
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

        FlawDownloadManager.started(flaw_id, self)

        set_user_acls(settings.ALL_GROUPS)

        # Code adapted from collectors.bzimport.collectors.FlawCollector.collect
        collector = collectors.FlawCollector()
        try:
            collector.sync_flaw(flaw_id)
        except Exception as e:
            FlawDownloadManager.failed(flaw_id, e)
        else:
            FlawDownloadManager.finished(flaw_id)
        finally:
            collector.free_queriers()

    def update_synced_links(self):
        from osidb.models import Flaw

        Flaw.objects.filter(meta_attr__bz_id=self.sync_id).update(download_manager=self)

    def __str__(self):
        from osidb.models import Flaw

        result = super().__str__()

        flaws = Flaw.objects.filter(meta_attr__bz_id=self.sync_id)
        cves = [f.cve_id or f.uuid for f in flaws]
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

        BZTrackerDownloadManager.started(tracker_id, self)

        set_user_acls(settings.ALL_GROUPS)

        # Code adapted from collectors.bzimport.collectors.BugzillaTrackerCollector.collect
        collector = collectors.BugzillaTrackerCollector()
        try:
            collector.sync_tracker(tracker_id)

            # Schedule linking tracker => affect
            BZTrackerLinkManager.schedule(tracker_id)
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
            tracker.save(raise_validation_error=False, auto_timestamps=False)

        return affects, failed_flaws, failed_affects

    @staticmethod
    @app.task(name="sync_manager.bz_tracker_link", bind=True)
    def sync_task(self, tracker_id):
        BZTrackerLinkManager.started(tracker_id, self)

        set_user_acls(settings.ALL_GROUPS)

        try:
            result = BZTrackerLinkManager.link_tracker_with_affects(tracker_id)
        except Exception as e:
            BZTrackerLinkManager.failed(tracker_id, e)
        else:
            # Handle link failures
            affects, failed_flaws, failed_affects = result
            if failed_flaws:
                BZTrackerLinkManager.failed(
                    tracker_id,
                    RuntimeError(
                        f"Flaws do not exist: {failed_flaws}, "
                        f"Affects do not exist: {failed_affects}"
                    ),
                )
            elif failed_affects:
                BZTrackerLinkManager.failed(
                    tracker_id,
                    RuntimeError(f"Affects do not exist: {failed_affects}"),
                    permanent=True,
                )
            elif not affects:
                BZTrackerLinkManager.failed(
                    tracker_id, RuntimeError("No Affects found")
                )
            else:
                BZTrackerLinkManager.finished(tracker_id)

    def update_synced_links(self):
        from osidb.models import Tracker

        Tracker.objects.filter(external_system_id=self.sync_id).update(
            bz_link_manager=self
        )

    def __str__(self):
        from osidb.models import Affect

        result = super().__str__()

        affects = Affect.objects.filter(trackers__external_system_id=self.sync_id)
        affect_strings = [
            f"{a.flaw.bz_id}|{a.ps_module}|{a.ps_component}" for a in affects
        ]
        result += f"Affects: {affect_strings}\n"

        return result


class BZSyncManager(SyncManager):
    """
    Sync manager class for OSIDB => Bugzilla synchronization.
    """

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
    def sync_task(self, flaw_id):
        # flaw_id is the flaw UUID
        from osidb.models import Flaw

        BZSyncManager.started(flaw_id, self)

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

    def __str__(self):
        from osidb.models import Flaw

        result = super().__str__()
        flaws = Flaw.objects.filter(uuid=self.sync_id)
        cves = [f.cve_id or f.uuid for f in flaws]
        result += f"Flaws: {cves}\n"

        return result


class JiraTaskDownloadManager(SyncManager):
    """
    Sync manager class for Jira => OSIDB Task synchronization.
    """

    @staticmethod
    @app.task(name="sync_manager.jira_task_download", bind=True)
    def sync_task(self, task_id):
        from collectors.jiraffe.convertors import JiraTaskConvertor
        from collectors.jiraffe.core import JiraQuerier

        JiraTaskDownloadManager.started(task_id, self)

        set_user_acls(settings.ALL_GROUPS)

        try:
            task_data = JiraQuerier().get_issue(task_id, expand="changelog")
            flaw = JiraTaskConvertor(task_data).flaw
            if flaw:
                flaw.save()
        except Exception as e:
            JiraTaskDownloadManager.failed(task_id, e)
        else:
            JiraTaskDownloadManager.finished(task_id)

    def update_synced_links(self):
        from osidb.models import Flaw

        Flaw.objects.filter(task_key=self.sync_id).update(task_download_manager=self)

    def __str__(self):
        from osidb.models import Flaw

        result = super().__str__()

        flaws = Flaw.objects.filter(task_key=self.sync_id)
        flaw_ids = [f.cve_id if f.cve_id else f.uuid for f in flaws]
        result += f"Jira tasks for flaws: {flaw_ids}\n"

        return result


class JiraTaskSyncManager(SyncManager):
    """
    Sync manager class for OSIDB => Jira Task synchronization.
    """

    @staticmethod
    @app.task(name="sync_manager.jira_task_sync", bind=True)
    def sync_task(self, flaw_id):
        """
        perform the sync of the task of the given flaw to Jira

        the task may not be existing yet when performing the first
        sync therefore we use the flaw UUID as the identifier
        """
        from osidb.models import Flaw

        JiraTaskSyncManager.started(flaw_id, self)

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

    def __str__(self):
        from osidb.models import Flaw

        result = super().__str__()
        flaws = Flaw.objects.filter(uuid=self.sync_id)
        cves = [f.cve_id or f.uuid for f in flaws]
        result += f"Flaws: {cves}\n"

        return result


class JiraTaskTransitionManager(SyncManager):
    """
    Transition manager class for OSIDB => Jira Task state synchronization.
    """

    @staticmethod
    @app.task(name="sync_manager.jira_task_transition", bind=True)
    def sync_task(self, flaw_id):
        """
        perform the sync of the task state of the given flaw to Jira

        the task must exist or otherwise the operation fails
        the flaw UUID is ensured so it is used as the identifier
        """
        from osidb.models import Flaw

        JiraTaskTransitionManager.started(flaw_id, self)

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

    def __str__(self):
        from osidb.models import Flaw

        result = super().__str__()
        flaws = Flaw.objects.filter(uuid=self.sync_id)
        cves = [f.cve_id or f.uuid for f in flaws]
        result += f"Flaws: {cves}\n"

        return result


class JiraTrackerDownloadManager(SyncManager):
    """
    Sync manager class for Jira => OSIDB Tracker synchronization.
    """

    @staticmethod
    @app.task(name="sync_manager.jira_tracker_download", bind=True)
    def sync_task(self, tracker_id):
        from collectors.jiraffe.convertors import JiraTrackerConvertor
        from collectors.jiraffe.core import JiraQuerier

        JiraTrackerDownloadManager.started(tracker_id, self)

        set_user_acls(settings.ALL_GROUPS)

        try:
            tracker_data = JiraQuerier().get_issue(tracker_id)
            tracker = JiraTrackerConvertor(tracker_data).tracker
            if tracker:
                tracker.save()
                # Schedule linking tracker => affect
                JiraTrackerLinkManager.schedule(tracker_id)
        except Exception as e:
            JiraTrackerDownloadManager.failed(tracker_id, e)
        else:
            JiraTrackerDownloadManager.finished(tracker_id)

    def update_synced_links(self):
        from osidb.models import Tracker

        Tracker.objects.filter(external_system_id=self.sync_id).update(
            jira_download_manager=self
        )

    def __str__(self):
        from osidb.models import Tracker

        result = super().__str__()

        trackers = Tracker.objects.filter(external_system_id=self.sync_id)
        tracker_ids = [t.external_system_id for t in trackers]
        result += f"Jira trackers: {tracker_ids}\n"

        return result


class JiraTrackerLinkManager(SyncManager):
    """
    Sync manager class for Jira => OSIDB Tracker synchronization where only links between
    Tracker and Affects are updated.
    """

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
            tracker.save(raise_validation_error=False, auto_timestamps=False)

        return affects, failed_flaws, failed_affects

    @staticmethod
    @app.task(name="sync_manager.jira_tracker_link", bind=True)
    def sync_task(self, tracker_id):
        JiraTrackerLinkManager.started(tracker_id, self)

        set_user_acls(settings.ALL_GROUPS)

        try:
            result = JiraTrackerLinkManager.link_tracker_with_affects(tracker_id)
        except Exception as e:
            JiraTrackerLinkManager.failed(tracker_id, e)
        else:
            # Handle link failures
            affects, failed_flaws, failed_affects = result
            if failed_flaws:
                JiraTrackerLinkManager.failed(
                    tracker_id,
                    RuntimeError(
                        f"Flaws do not exist: {failed_flaws}, "
                        f"Affects do not exist: {failed_affects}"
                    ),
                )
            elif failed_affects:
                JiraTrackerLinkManager.failed(
                    tracker_id,
                    RuntimeError(f"Affects do not exist: {failed_affects}"),
                    permanent=True,
                )
            elif not affects:
                JiraTrackerLinkManager.failed(
                    tracker_id, RuntimeError("No Affects found")
                )
            else:
                JiraTrackerLinkManager.finished(tracker_id)

    def update_synced_links(self):
        from osidb.models import Tracker

        Tracker.objects.filter(external_system_id=self.sync_id).update(
            jira_link_manager=self
        )

    def __str__(self):
        from osidb.models import Affect

        result = super().__str__()

        affects = Affect.objects.filter(trackers__external_system_id=self.sync_id)
        affect_strings = [
            f"{a.flaw.bz_id}|{a.ps_module}|{a.ps_component}" for a in affects
        ]
        result += f"Affects: {affect_strings}\n"

        return result
