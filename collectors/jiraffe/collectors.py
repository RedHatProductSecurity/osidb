"""
Jira collector
"""
from typing import List, Union

from celery.utils.log import get_task_logger
from django.utils import timezone
from jira import Issue

from collectors.framework.models import Collector

from .convertors import TrackerIssueConvertor
from .core import JiraQuerier

logger = get_task_logger(__name__)


class JiraTrackerCollector(Collector, JiraQuerier):
    """
    Jira tracker collector
    """

    # date before the first Jira tracker was created (or at least the oldest update)
    BEGINNING = timezone.datetime(2014, 1, 1, tzinfo=timezone.get_current_timezone())
    # Jira API does not seem to have either issues returning large number of results
    # or any restrictions on the maximum query period so we can be quite greedy
    BATCH_PERIOD_DAYS = 365

    def get_batch(self) -> (List[Issue], timezone.datetime):
        """
        get next batch of Jira trackers plus period_end timestamp
        """
        period_start = self.metadata.updated_until_dt or self.BEGINNING
        period_end = period_start + timezone.timedelta(days=self.BATCH_PERIOD_DAYS)
        # query for trackers in the period and return them together with the timestamp
        return self.get_tracker_period(period_start, period_end), period_end

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
            else ([self.get_issue(tracker_id)], None)
        )

        # process data
        for tracker_data in batch_data:
            tracker_convertor = TrackerIssueConvertor(tracker_data)
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

        msg = f"{self.name} is updated until {updated_until_dt}."
        msg += (
            f" Jira trackers updated: {', '.join(updated_trackers)}"
            if updated_trackers
            else ""
        )

        logger.info("Jira tracker sync was successful.")
        return msg
