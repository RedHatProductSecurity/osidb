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

from apps.trackers.models import JiraProjectFields
from collectors.framework.models import Collector
from osidb.models import PsModule

from .convertors import JiraTrackerConvertor
from .core import JiraQuerier
from .exceptions import MetadataCollectorInsufficientDataJiraffeException

logger = get_task_logger(__name__)


class JiraTrackerCollector(Collector):
    """
    Jira tracker collector
    """

    # date before the first Jira tracker was created (or at least the oldest update)
    BEGINNING = timezone.datetime(2014, 1, 1, tzinfo=timezone.get_current_timezone())
    # Jira API does not seem to have either issues returning large number of results
    # or any restrictions on the maximum query period so we can be quite greedy
    BATCH_PERIOD_DAYS = 365

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
        start_dt = timezone.now()
        updated_trackers = []

        # fetch the next batch of Jira trackers by default
        # but can be overridden by a given tracker ID
        batch_data, period_end = (
            self.get_batch()
            if tracker_id is None
            else ([self.jira_querier.get_issue(tracker_id)], None)
        )

        # process data
        for tracker_data in batch_data:
            tracker_convertor = JiraTrackerConvertor(tracker_data)
            tracker = tracker_convertor.convert()
            # no automatic timestamps as those go from Jira
            # and no validation exceptions not to fail here
            tracker.save(auto_timestamps=False, raise_validation_error=False)

            updated_trackers.append(tracker.external_system_id)

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
