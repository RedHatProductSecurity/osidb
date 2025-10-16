"""
Jira collector
"""

from time import sleep
from typing import List, Optional, Union

from celery.utils.log import get_task_logger
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from jira import Issue
from jira.exceptions import JIRAError

from apps.taskman.service import JiraTaskmanQuerier
from apps.trackers.models import JiraProjectFields
from collectors.framework.models import Collector
from osidb.models import PsModule
from osidb.sync_manager import (
    JiraTaskDownloadManager,
    JiraTrackerDownloadManager,
)

from .constants import JIRA_EMAIL, JIRA_TOKEN
from .convertors import JiraTaskConvertor, JiraTrackerConvertor
from .core import JiraQuerier
from .exceptions import MetadataCollectorInsufficientDataJiraffeException

logger = get_task_logger(__name__)


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
            self._jira_querier = JiraTaskmanQuerier(JIRA_TOKEN, JIRA_EMAIL)
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

        # single-task sync
        if task_id is not None:
            task_data = self.jira_querier.get_issue(task_id, expand="changelog")
            flaw = JiraTaskConvertor(task_data).flaw
            if flaw:
                self.save(flaw)
            return f"Jira task sync of {task_id} completed"

        # multi-task sync
        start_dt = timezone.now()
        updated_tasks = []

        JiraTaskDownloadManager.check_for_reschedules()

        batch_data, period_end = self.get_batch()

        # schedule data sync
        for task in batch_data:
            JiraTaskDownloadManager.schedule(task.key)
            updated_tasks.append(task.key)

        logger.info(
            f"Flaw update was scheduled for the following task IDs: {', '.join(updated_tasks)}"
            if updated_tasks
            else "No Flaw were updated."
        )

        # when we get to the future with the period end
        # the initial sync is done and the data are complete
        updated_until_dt = min(start_dt, period_end)
        complete = start_dt == updated_until_dt or self.metadata.is_complete
        self.store(complete=complete, updated_until_dt=updated_until_dt)

        # Remove querier objects and close unneeded connection when collector task is finished
        self.free_queriers()

        msg = f"{self.name} is updated until {updated_until_dt}."
        msg += (
            f"Flaw update scheduled for Jira tasks: {', '.join(updated_tasks)}"
            if updated_tasks
            else ""
        )

        logger.info("Jira tasks sync scheduled successfully.")
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
        logger.info("Fetching Jira trackers")

        # single-tracker sync
        if tracker_id is not None:
            tracker_data = self.jira_querier.get_issue(tracker_id)
            tracker = JiraTrackerConvertor(tracker_data).tracker
            if tracker:
                self.save(tracker)
            return f"Jira tracker sync of {tracker_id} completed"

        # multi-tracker sync
        start_dt = timezone.now()
        updated_trackers = []

        JiraTrackerDownloadManager.check_for_reschedules()

        batch_data, period_end = self.get_batch()

        # schedule data sync
        for tracker in batch_data:
            JiraTrackerDownloadManager.schedule(tracker.key)
            updated_trackers.append(tracker.key)

        logger.info(
            f"Jira tracker sync was scheduled for the following IDs: {', '.join(updated_trackers)}"
            if updated_trackers
            else "No Jira trackers were updated."
        )

        # when we get to the future with the period end
        # the initial sync is done and the data are complete
        updated_until_dt = min(start_dt, period_end)
        complete = start_dt == updated_until_dt or self.metadata.is_complete
        self.store(complete=complete, updated_until_dt=updated_until_dt)

        # Remove querier objects and close unneeded connection when collector task is finished
        self.free_queriers()

        msg = f"{self.name} is updated until {updated_until_dt}."
        msg += (
            f" Jira tracker sync scheduled: {', '.join(updated_trackers)}"
            if updated_trackers
            else ""
        )

        logger.info("Jira tracker sync scheduled successfully.")
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

        Historically, trackers were of issue type Bug and this issue type had number 1.
        New trackers are of issue type Vulnerability and this issue type has number 12207.
        Presuming the Bug type with number 1 is set in stone, but the Vulnerability 12207
        can move to a new number.

        For fields that are shared by both issue types but have different configuration,
        the Vulnerability issue type wins and its version of those fields is stored.
        This is because new trackers will use the new Vulnerability issue type going forward
        and the Bug/1 issue type is kept only for backwards compatibility with existing
        trackers.
        """
        id_of_vulnerability_issue_type = None

        try:
            res = self.jira_querier.jira_conn._get_json("issuetype")
            for t in res:
                if t["name"] == "Vulnerability":
                    id_of_vulnerability_issue_type = t["id"]
                    break
        except JIRAError as e:
            if e.status_code == 400:
                logger.error(
                    "List of issue types (rest/api/2/issuetype) is not available in Jira, make sure API key and jira library version are set up as expected."
                )
            else:
                logger.error(
                    f"Jira error trying to fetch issue types (rest/api/2/issuetype): {e.response}"
                )
        issue_types = ["1"]
        if id_of_vulnerability_issue_type:
            issue_types.insert(0, id_of_vulnerability_issue_type)  # prepend to list

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
        projects_already_collected = set()
        for issuetype in issue_types:
            for project in projects:
                if project in projects_already_collected:
                    continue
                page_size = 100
                start_at = 0
                is_last = False
                try:
                    # here we repeatedly hit the rate limiting probably by firing the requrests too
                    # fast after each other so let us introduce a short delay - there is no danger
                    # of race condition as this collector is the only code writing this metadata
                    sleep(1)
                    if project not in project_fields:
                        project_fields[project] = []
                    while not is_last:
                        res = self.jira_querier.jira_conn._get_json(
                            f"issue/createmeta/{project}/issuetypes/{issuetype}?startAt={start_at}&maxResults={page_size}"
                        )

                        project_fields[project].extend(res["fields"])
                        total = res.get("total", 0)
                        max_results = res.get("maxResults", page_size)
                        start_at += max_results
                        is_last = start_at >= total
                    projects_already_collected.add(project)
                except JIRAError as e:
                    if e.status_code == 400:
                        logger.error(
                            f"Project {project} is not available in Jira for issuetype {issuetype}, make sure product definition is up to date."
                        )
                    else:
                        logger.error(
                            f"Jira error trying to fetch project {project} for issuetype {issuetype}: {e.response}"
                        )

        nonempty_project_fields = {k: v for k, v in project_fields.items() if v}
        if len(nonempty_project_fields) < projects.count() * 0.8:
            logger.error(
                "More than 20% of projects are not available in Jira. Make sure jira token is valid and product definition is up to date."
            )
            # Proceeding would erase existing JiraProjectField models and would make it impossible
            # to work with Jira-based Trackers. Raising will preserve the (slightly outdated) data.
            raise MetadataCollectorInsufficientDataJiraffeException

        projects_to_delete = list(
            JiraProjectFields.objects.values_list("project_key", flat=True)
            .distinct()
            .difference(projects)
        )
        self.update_metadata(
            nonempty_project_fields, projects_to_delete=projects_to_delete
        )

        self.store(updated_until_dt=start_dt)

        # Remove querier objects and close unneeded connection when collector task is finished
        self.free_queriers()

        logger.info(f"{self.name} is updated until {start_dt}")
        return f"{self.name} is updated until {start_dt}: {len(project_fields)} Jira projects' metadata fetched"

    @transaction.atomic
    def update_metadata(
        self, project_fields, projects_to_delete: Optional[list] = None
    ):
        """
        remove old and store new Jira projects' metadata
        inside an atomic transaction
        """
        if projects_to_delete is None:
            projects_to_delete = []

        JiraProjectFields.objects.filter(project_key__in=projects_to_delete).delete()

        for project_key, fields in project_fields.items():
            fields_to_create = []
            for field in fields:
                allowed_values = [
                    av.get("name", av.get("value"))
                    for av in field.get("allowedValues", {})
                ]
                field = JiraProjectFields(
                    project_key=project_key,
                    field_id=field["fieldId"],
                    field_name=field["name"],
                    allowed_values=allowed_values,
                )
                fields_to_create.append(field)
            JiraProjectFields.objects.filter(project_key=project_key).delete()
            JiraProjectFields.objects.bulk_create(fields_to_create)
