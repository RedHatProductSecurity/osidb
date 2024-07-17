"""
Jira collector
"""

from typing import List, Union

from celery.utils.log import get_task_logger
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from jira import Issue
from jira.exceptions import JIRAError

from apps.taskman.service import JiraTaskmanQuerier
from apps.trackers.models import JiraProjectFields
from collectors.framework.models import Collector, CollectorMetadata
from osidb.models import Affect, Flaw, PsModule, Tracker
from osidb.sync_manager import JiraTrackerLinkManager

from .constants import JIRA_TOKEN
from .convertors import JiraTaskConvertor, JiraTrackerConvertor
from .core import JiraQuerier
from .exceptions import (
    JiraTrackerCollectorConcurrentEditAvoided,
    MetadataCollectorInsufficientDataJiraffeException,
)

logger = get_task_logger(__name__)


# TODO use select_for_update appropriately. See SelectForUpdateMixin for reasoning.
class JiraTaskCollector(Collector):
    """
    Jira task collector
    """

    # date before the first Jira task was created (or at least the oldest update)
    BEGINNING = timezone.datetime(2024, 2, 21, tzinfo=timezone.get_current_timezone())
    # Jira API does not seem to have either issues returning large number of results
    # or any restrictions on the maximum query period so we can be quite greedy
    BATCH_PERIOD_DAYS = 10

    def __init__(self):
        super().__init__()
        self._jira_querier = None

    @property
    def jira_querier(self):
        if self._jira_querier is None:
            self._jira_querier = JiraTaskmanQuerier(JIRA_TOKEN)
        return self._jira_querier

    def free_queriers(self):
        self._jira_querier = None

    def get_batch(self) -> (List[Issue], timezone.datetime):
        """
        get next batch of Jira tasks plus period_end timestamp
        """
        period_start = self.metadata.updated_until_dt or self.BEGINNING
        period_end = period_start + timezone.timedelta(days=self.BATCH_PERIOD_DAYS)

        # query for tasks in the period and return them together with the timestamp
        return (
            self.jira_querier.get_task_period(period_start, period_end),
            period_end,
        )

    def collect(self, task_id: Union[str, None] = None) -> str:
        """
        collector run handler

        on every run the next batch of Jira tasks is fetched and store
        while proceeding forward by the timestamp of the last update
        """
        logger.info("Fetching Jira tasks")
        start_dt = timezone.now()
        updated_tasks = []
        batch_data, period_end = (
            self.get_batch()
            if task_id is None
            else ([self.jira_querier.get_issue(task_id)], None)
        )

        # process data
        for task_data in batch_data:
            # perform this as a transaction to avoid
            # collision between loading and saving the flaw
            with transaction.atomic():
                flaw = JiraTaskConvertor(task_data).flaw
                if flaw:
                    self.save(flaw)
                    updated_tasks.append(task_data.key)

        logger.info(
            f"Flaws were updated for the following task IDs: {', '.join(updated_tasks)}"
            if updated_tasks
            else "No Flaw were updated."
        )

        if task_id is not None:
            return f"Jira task sync of {task_id} completed"

        # when we get to the future with the period end
        # the initial sync is done and the data are complete
        updated_until_dt = min(start_dt, period_end)
        complete = start_dt == updated_until_dt or self.metadata.is_complete
        self.store(complete=complete, updated_until_dt=updated_until_dt)

        # Remove querier objects and close unneeded connection when collector task is finished
        self.free_queriers()

        msg = f"{self.name} is updated until {updated_until_dt}."
        msg += (
            f"Flaws updated for Jira tasks: {', '.join(updated_tasks)}"
            if updated_tasks
            else ""
        )

        logger.info("Jira tasks sync was successful.")
        return msg


class JiraTrackerCollector(Collector):
    """
    Jira tracker collector
    """

    # date before the first Jira tracker was created (or at least the oldest update)
    BEGINNING = timezone.datetime(2014, 1, 1, tzinfo=timezone.get_current_timezone())
    # Jira API does not seem to have either issues returning large number of results
    # or any restrictions on the maximum query period so we can be quite greedy
    BATCH_PERIOD_DAYS = 10

    def __init__(self):
        super().__init__()
        self._jira_querier = None

    @property
    def jira_querier(self):
        if self._jira_querier is None:
            self._jira_querier = JiraQuerier()
        return self._jira_querier

    def free_queriers(self):
        self._jira_querier = None

    def get_batch(self) -> (List[Issue], timezone.datetime):
        """
        get next batch of Jira trackers plus period_end timestamp
        """
        period_start = self.metadata.updated_until_dt or self.BEGINNING
        period_end = period_start + timezone.timedelta(days=self.BATCH_PERIOD_DAYS)
        # the tracker collector should never outrun the flaw one
        # since it creates the linkage which might then be missed
        period_end = min(
            period_end,
            CollectorMetadata.objects.get(
                name="collectors.bzimport.tasks.flaw_collector"
            ).updated_until_dt
            or period_end,
        )
        # query for trackers in the period and return them together with the timestamp
        return (
            self.jira_querier.get_tracker_period(period_start, period_end),
            period_end,
        )

    def collect(self, tracker_id: Union[str, None] = None) -> str:
        """
        collector run handler

        on every run the next batch of Jira trackers is fetched and store
        while proceeding forward by the timestamp of the last update

        tracker_id param makes the collector to sync a tracker of the given ID only
        """

        logger.info("Fetching Jira trackers (start)")
        start_dt = timezone.now()
        updated_trackers = []

        if tracker_id:
            related_tracker_uuids = set(
                Tracker.objects.filter(external_system_id=tracker_id).values_list(
                    "uuid", flat=True
                )
            )
            tracker_orig_model_updated_dts = set(
                Tracker.objects.filter(uuid__in=related_tracker_uuids).values_list(
                    "updated_dt", flat=True
                )
            )
            related_affect_uuids = set(
                Tracker.objects.filter(uuid__in=related_tracker_uuids).values_list(
                    "affects__uuid", flat=True
                )
            )
            related_flaw_uuids = set(
                Affect.objects.filter(uuid__in=related_affect_uuids).values_list(
                    "flaw__uuid", flat=True
                )
            )
            flaw_orig_model_updated_dts = set(
                Flaw.objects.filter(uuid__in=related_flaw_uuids).values_list(
                    "updated_dt", flat=True
                )
            )
            logger.info(
                f"Fetching Jira trackers (id {tracker_id}, original tracker updated_dt {tracker_orig_model_updated_dts}, orig. flaw updated_dt {flaw_orig_model_updated_dts})"
            )

        JiraTrackerLinkManager.check_for_reschedules()

        # fetch the next batch of Jira trackers by default
        # but can be overridden by a given tracker ID
        batch_data, period_end = (
            self.get_batch()
            if tracker_id is None
            else ([self.jira_querier.get_issue(tracker_id)], None)
        )

        # ...getting here might take a while, so locking only now,
        # so as to minimize blocking API for clients editing the
        # same tracker or the related affects or flaws.
        # Despite later tracker => affect linking, affects are
        # also manipulated within JiraTrackerConvertor, hence
        # locking all Flaw(s), Affect(s) and the Tracker(s),
        # also because of reasons explained in SelectForUpdateMixin.

        with transaction.atomic():
            # Prevent locking multiple times, although Postgresql would probably accept it.
            locked_flaw_uuids = set()
            locked_affect_uuids = set()
            locked_tracker_uuids = set()

            # For reasoning about locking and order of locking, see SelectForUpdateMixin.

            if tracker_id:
                Flaw.objects.filter(uuid__in=related_flaw_uuids).select_for_update()
                locked_flaw_uuids.update(related_flaw_uuids)
                Affect.objects.filter(uuid__in=related_affect_uuids).select_for_update()
                locked_affect_uuids.update(related_affect_uuids)
                Tracker.objects.filter(
                    uuid__in=related_tracker_uuids
                ).select_for_update()
                locked_tracker_uuids.update(related_tracker_uuids)

            # process data with locking them first
            for tracker_data in batch_data:

                this_external_system_id = tracker_data.key
                this_flaw_uuids = set()
                this_affect_uuids = set()
                this_tracker_uuid = None
                for lbl in tracker_data.fields.labels:
                    if lbl.startswith("flawuuid:"):
                        this_flaw_uuids.add(lbl.split(":")[1])

                this_tracker_queryset = Tracker.objects.filter(
                    external_system_id=this_external_system_id,
                    type=Tracker.TrackerType.JIRA,
                )
                if this_tracker_queryset.exists():
                    this_tracker_uuid = this_tracker_queryset.first().uuid
                    this_affect_uuids.update(
                        set(
                            Tracker.objects.filter(uuid=this_tracker_uuid).values_list(
                                "affects__uuid", flat=True
                            )
                        )
                    )
                    this_flaw_uuids.update(
                        set(
                            Affect.objects.filter(
                                uuid__in=this_affect_uuids
                            ).values_list("flaw__uuid", flat=True)
                        )
                    )
                this_affect_uuids.update(
                    set(
                        Flaw.objects.filter(uuid__in=this_flaw_uuids).values_list(
                            "affects__uuid", flat=True
                        )
                    )
                )

                this_yet_unlocked_flaw_uuids = this_flaw_uuids - locked_flaw_uuids
                Flaw.objects.filter(
                    uuid__in=this_yet_unlocked_flaw_uuids
                ).select_for_update()
                locked_flaw_uuids.update(this_yet_unlocked_flaw_uuids)

                this_yet_unlocked_affect_uuids = this_affect_uuids - locked_affect_uuids
                Affect.objects.filter(
                    uuid__in=this_yet_unlocked_affect_uuids
                ).select_for_update()
                locked_affect_uuids.update(this_yet_unlocked_affect_uuids)

                if this_tracker_uuid not in locked_tracker_uuids:
                    Tracker.objects.filter(uuid=this_tracker_uuid).select_for_update()
                    locked_tracker_uuids.add(this_tracker_uuid)

                if tracker_id:
                    tracker_current_model_updated_dts = set(
                        Tracker.objects.filter(
                            uuid__in=related_tracker_uuids
                        ).values_list("updated_dt", flat=True)
                    )
                    flaw_current_model_updated_dts = set(
                        Flaw.objects.filter(uuid__in=related_flaw_uuids).values_list(
                            "updated_dt", flat=True
                        )
                    )
                    if (
                        tracker_orig_model_updated_dts
                        != tracker_current_model_updated_dts
                    ) or (
                        flaw_orig_model_updated_dts != flaw_current_model_updated_dts
                    ):
                        logger.info(
                            f"Fetching Jira trackers (detected concurrent edit, id {tracker_id}, current tracker updated_dt {tracker_current_model_updated_dts}, curr. flaw updated_dt {flaw_current_model_updated_dts})"
                        )
                        raise JiraTrackerCollectorConcurrentEditAvoided

                # perform the tracker save itself
                tracker = JiraTrackerConvertor(tracker_data).tracker
                self.save(tracker)
                updated_trackers.append(tracker_data.key)

        # Schedule linking tracker => affect
        for updated_tracker_id in updated_trackers:
            JiraTrackerLinkManager.schedule(updated_tracker_id)

        logger.info(
            f"Jira trackers were updated for the following IDs: {', '.join(updated_trackers)}"
            if updated_trackers
            else "No Jira trackers were updated."
        )

        # do not update the collector metadata
        # when ad-hoc collecting a given tracker
        if tracker_id is not None:
            return f"Jira tracker sync of {tracker_id} completed"

        # when we get to the future with the period end
        # the initial sync is done and the data are complete
        updated_until_dt = min(start_dt, period_end)
        complete = start_dt == updated_until_dt or self.metadata.is_complete
        self.store(complete=complete, updated_until_dt=updated_until_dt)

        # Remove querier objects and close unneeded connection when collector task is finished
        self.free_queriers()

        msg = f"{self.name} is updated until {updated_until_dt}."
        msg += (
            f" Jira trackers updated: {', '.join(updated_trackers)}"
            if updated_trackers
            else ""
        )

        logger.info("Jira tracker sync was successful.")
        return msg


class MetadataCollector(Collector):
    """
    Jira metadata collector
    to collect data on Jira Project fields
    """

    def __init__(self):
        super().__init__()
        self._jira_querier = None

    @property
    def jira_querier(self):
        if self._jira_querier is None:
            self._jira_querier = JiraQuerier()
        return self._jira_querier

    def free_queriers(self):
        self._jira_querier = None

    def collect(self):
        """
        collector run handler
        """
        start_dt = timezone.now()
        projects = (
            PsModule.objects.exclude(
                Q(bts_name="bugzilla")
                | Q(active_ps_update_streams__isnull=True)
                | Q(supported_until_dt__lt=start_dt)
            )
            .values_list("bts_key", flat=True)
            .distinct()
        )

        project_fields = {}
        for project in projects:
            page_size = 100
            start_at = 0
            is_last = False
            try:
                project_fields[project] = []
                while not is_last:
                    res = self.jira_querier.jira_conn._get_json(
                        f"issue/createmeta/{project}/issuetypes/1?startAt={start_at}&maxResults={page_size}"
                    )
                    project_fields[project].extend(res["values"])
                    page_size = res["maxResults"]
                    start_at += page_size
                    is_last = res["isLast"]
            except JIRAError as e:
                if e.status_code == 400:
                    print(e.response)
                    logger.error(
                        f"Project {project} is not available in Jira, make sure product definition is up to date."
                    )
                else:
                    logger.error(
                        f"Jira error trying to fetch project {project}: {e.response}"
                    )
        nonempty_project_fields = {k: v for k, v in project_fields.items() if v}
        if len(nonempty_project_fields) < projects.count() * 0.8:
            logger.error(
                "More than 20% of projects are not available in Jira. Make sure jira token is valid and product definition is up to date."
            )
            # Proceeding would erase existing JiraProjectField models and would make it impossible
            # to work with Jira-based Trackers. Raising will preserve the (slightly outdated) data.
            raise MetadataCollectorInsufficientDataJiraffeException

        self.update_metadata(project_fields)

        self.store(updated_until_dt=start_dt)

        # Remove querier objects and close unneeded connection when collector task is finished
        self.free_queriers()

        logger.info(f"{self.name} is updated until {start_dt}")
        return f"{self.name} is updated until {start_dt}: {len(project_fields)} Jira projects' metadata fetched"

    @transaction.atomic
    def update_metadata(self, project_fields):
        """
        remove old and store new Jira projects' metadata
        inside an atomic transaction
        """
        JiraProjectFields.objects.all().delete()

        for project_key, fields in project_fields.items():
            for field in fields:
                if "allowedValues" in field:
                    allowed_values = [
                        av.get("name", av.get("value")) for av in field["allowedValues"]
                    ]
                else:
                    allowed_values = []
                field = JiraProjectFields(
                    project_key=project_key,
                    field_id=field["fieldId"],
                    field_name=field["name"],
                    allowed_values=allowed_values,
                )
                field.save()
