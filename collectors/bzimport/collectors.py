"""
Bugzilla collector
"""
import json
from typing import Union

import bugzilla
import requests_cache
from bugzilla.base import Bugzilla
from celery.utils.log import get_task_logger
from dateutil.relativedelta import relativedelta
from django.utils import timezone
from requests_gssapi import HTTPKerberosAuth

from collectors.bzimport.convertors import FlawBugConvertor, TrackerBugConvertor
from collectors.bzimport.srtnotes_parser import parse_cf_srtnotes
from collectors.framework.models import Collector
from collectors.jiraffe.core import JiraQuerier
from osidb.models import Flaw, Tracker

from .constants import (
    ANALYSIS_TASK_PRODUCT,
    BZ_API_KEY,
    BZ_DT_FMT,
    BZ_URL,
    NVD_CVSS_URL,
    ROOT_CA_PATH,
)
from .exceptions import BZImportException

logger = get_task_logger(__name__)


class BugzillaQuerier:
    """Bugzilla query handler"""

    # Bugzilla API limit - 20 is default
    # query result is cut when exceeding the limit
    #
    # 20 is the default but we set the limit to the maximum
    # by explicitely giving it 0 value and the maximum is 1000
    # this enhances the queries significantly
    BZ_API_LIMIT = 1000

    #######################
    # BUGZILLA CONNECTION #
    #######################

    _bz_conn = None

    def create_bz_conn(self) -> Bugzilla:
        """create Bugzilla connection"""
        bz_conn = bugzilla.Bugzilla(url=BZ_URL, api_key=BZ_API_KEY, force_rest=True)
        if not bz_conn.logged_in:
            raise BZImportException("Cannot access Bugzilla")
        return bz_conn

    @property
    def bz_conn(self) -> Bugzilla:
        """get Bugzilla connection"""
        if self._bz_conn is None:
            self._bz_conn = self.create_bz_conn()

        return self._bz_conn

    ######################
    # SINGLE BUG QUERIES #
    ######################

    def get_bug(self, bz_id, include_fields=None):
        """get Bugzilla bug"""
        return self.bz_conn.getbug(bz_id, include_fields=include_fields)

    def get_bug_data(self, bz_id, include_fields=None):
        """get Bugzilla bug data"""
        return self.get_bug(bz_id, include_fields=include_fields).get_raw_data()

    def get_bug_history(self, bz_id):
        """get Bugzilla bug history"""
        # return self.get_bug(bz_id).get_history_raw()
        # TODO temporarily disabled - returns empty history immediately
        return {"bugs": [{"history": []}]}

    def get_bug_comments(self, bz_id):
        """get Bugzilla bug comments"""
        return self.get_bug(bz_id).getcomments()

    ###################
    # QUERY MODIFIERS #
    ###################

    def query_last_updated(self, query, updated_after=None, updated_before=None):
        """extend the query with conditions on last change time"""
        if not updated_before and not updated_after:
            return query

        if not updated_before:
            addition = {"last_change_time": updated_after}

        elif not updated_after:
            addition = {
                "f1": "delta_ts",
                "o1": "lessthaneq",
                "v1": updated_before,
            }

        else:
            addition = {
                "f1": "delta_ts",
                "f2": "delta_ts",
                # > updated_after and <= updated_before
                "o1": "greaterthan",
                "o2": "lessthaneq",
                "v1": updated_after,
                "v2": updated_before,
                "query_format": "advanced",
            }

        query.update(addition)
        return query

    def query_greaterthan_id(self, query, bug_id):
        """extend query with greaterthan bug ID condition"""
        query = dict(query)
        query["query_format"] = "advanced"
        query["f98"] = "bug_id"
        query["o98"] = "greaterthan"
        query["v98"] = str(bug_id)
        return query

    def query_maximum(self, query):
        """
        extend query limit to API maximum
        stored in BZ_API_LIMIT above (1000)
        """
        query = dict(query)
        query["limit"] = self.BZ_API_LIMIT
        return query

    #####################
    # MULTI BUG QUERIES #
    #####################

    def query_all_flaws(self):
        """general query for all flaws"""
        return {
            "product": "Security Response",
            "component": "vulnerability",
            "include_fields": ["id", "last_change_time", "summary"],
        }

    def get_ids(self, query, updated_after=None, updated_before=None):
        """get bug IDs based on given query with optional updated time restriction"""
        return sorted(
            self.run_query(
                self.query_last_updated(
                    query,
                    updated_after,
                    updated_before,
                )
            ),
            key=lambda x: x[1],  # sort by ascending last change time
        )

    def run_query(self, query):
        """
        query for Bugzilla bugs
        returns IDs and last change times as list of tupples
        """
        query = self.query_maximum(query)
        updated_query = query
        bugs = []

        while True:
            query_result = self.bz_conn.query(updated_query)
            bugs.extend(
                (
                    str(bug.id),
                    timezone.datetime.strptime(bug.last_change_time, BZ_DT_FMT),
                    bug.summary,
                )
                for bug in query_result
            )

            if len(query_result) != self.BZ_API_LIMIT:
                break

            # update the query to look for bugs following the max ID
            max_bug_id = max(
                int(record[0]) for record in bugs
            )  # assume first col is bug ID
            updated_query = self.query_greaterthan_id(query, max_bug_id)

        return self.exclude_testing(bugs)

    ###########
    # HELPERS #
    ###########

    @staticmethod
    def exclude_testing(bugs):
        """
        filter out the testing bugs and bug summaries and
        eventually delete corresponding flaws from the DB

        the convention from SFM2 times to recognize testing
        bugs is that their summary starts with testing:

        we do not filter this on the query level as in that case
        we would have no information that a bug becomes testing so
        we would not be able to reflect it by removing the data
        """
        non_testing = []

        for bug_id, last_change_time, summary in bugs:
            if not summary.lower().startswith("testing:"):
                non_testing.append((bug_id, last_change_time))
                continue

            # let us consider all bugs as flaws for now
            flaw = Flaw.objects.filter(meta_attr__bz_id=bug_id).first()
            if flaw is not None:
                flaw.delete()

        return non_testing


# TODO
# this is a very dummy solution which works but
# should be eventually turned into a collector
class NVDQuerier:
    """NVD query handler"""

    _nvd_cvss = None
    _timestamp = None

    @staticmethod
    def get_nvd_cvss() -> dict:
        """returns a dict with all NVD CVSS"""
        session = requests_cache.CachedSession("bzimport_requests_cache")
        response = session.get(
            NVD_CVSS_URL,
            verify=ROOT_CA_PATH,
            auth=HTTPKerberosAuth(),
        )
        if not response.ok:
            return {}
        return response.json()

    @classmethod
    def nvd_cvss(cls) -> dict:
        """
        cached NVD CVSS getter
        recached every hour
        """
        if cls._nvd_cvss is None or (
            timezone.now() - cls._timestamp
        ) > timezone.timedelta(hours=1):
            cls._nvd_cvss = cls.get_nvd_cvss()
            cls._timestamp = timezone.now()

        return cls._nvd_cvss


class FlawCollector(Collector, BugzillaQuerier, JiraQuerier):
    """Bugzilla flaw collector"""

    # date before the first flaw was created
    BEGINNING = timezone.datetime(2000, 1, 1, tzinfo=timezone.get_current_timezone())

    # this should be considered the minimum amount of flaws to be synced
    # per collector run and not a hard limit per batch, as each batch will
    # most likely contain more than this, but not less unless it's the last run
    BATCH_SIZE = 100

    def end_period_heuristic(self, period_start):
        """
        very simple heuristic to optimize the batch period
        basically in the past there are a few flaws every year
        but recently there is a lot of them every week
        and there was one problematic data migration
        """
        # TODO tzinfo here and on other places should be set implicitly
        # but my current attempts do not work - leaving explicit for now
        if period_start < timezone.datetime(
            2010, 1, 1, tzinfo=timezone.get_current_timezone()
        ):
            return period_start + relativedelta(years=5)

        if period_start < timezone.datetime(
            2018, 1, 1, tzinfo=timezone.get_current_timezone()
        ):
            return period_start + relativedelta(years=1)

        # there was a huge data migration between
        # 2019-09-29 12:19:32 - 2019-09-29 15:37:58
        # so we prevent very long query going by minute

        MIGRATION_START = timezone.datetime(
            2019, 9, 29, 12, 19, tzinfo=timezone.get_current_timezone()
        )
        MIGRATION_END = timezone.datetime(
            2019, 9, 29, 15, 38, tzinfo=timezone.get_current_timezone()
        )

        if period_start < MIGRATION_START:
            return MIGRATION_START

        if period_start < MIGRATION_END:
            return period_start + relativedelta(minutes=1)

        # then we have more regularly scattered data
        # and the possible future date is no problem
        # so we can use it for the periodic sync too
        return period_start + relativedelta(months=1)

    def get_batch(self):
        """get next batch of flaw IDs"""
        period_start = self.metadata.updated_until_dt or self.BEGINNING
        period_end = self.end_period_heuristic(period_start)

        while True:
            flaw_ids = self.get_flaw_ids(period_start, period_end)

            if len(flaw_ids) < self.BATCH_SIZE and period_end < timezone.now():
                # if the set of fetched flaws is too small, fetch some more
                period_end = self.end_period_heuristic(period_end)
                continue

            # return all fetched flaw_ids, that way we can ensure that
            # all flaws for the given time range have been fetched
            # and on the next batch we can fetch strictly greater than period_end
            return flaw_ids

    def get_flaw_ids(self, updated_after=None, updated_before=None):
        """get flaw IDs with optional updated time restriction"""
        return self.get_ids(self.query_all_flaws(), updated_after, updated_before)

    def get_flaw_bz_trackers(self, flaw_data: dict) -> list:
        """get Bugzilla trackers from flaw data"""
        bz_trackers = []

        for bz_id in flaw_data["depends_on"]:
            bug = self.get_bug_data(bz_id)
            # security tracking Bugzilla bug has always SecurityTracking keyword
            # there may be any other non-tracker bugs in the depends_on field
            if "SecurityTracking" in bug["keywords"]:
                bz_trackers.append(bug)

        return bz_trackers

    def get_flaw_jira_trackers(self, flaw_data: dict) -> list:
        """get Jira trackers from flaw data"""
        jira_trackers = []

        for jira_id in self.get_flaw_jira_tracker_ids(flaw_data):
            jira_trackers.append(self.get_issue(jira_id))

        return jira_trackers

    def get_flaw_jira_tracker_ids(self, flaw_data: dict) -> list:
        """get Jira tracker IDs from Bugzilla flaw data"""
        try:
            return [
                issue["key"]
                for issue in parse_cf_srtnotes(flaw_data["cf_srtnotes"]).get(
                    "jira_trackers", []
                )
            ]
        except json.decoder.JSONDecodeError:
            # this exception means invalid or empty SRT notes which usually means a very old flaw
            # here let us just consider it as that there are no Jira trackers attached to the flaw
            return []

    def get_flaw_task(self, flaw_data: dict) -> Union[str, None]:
        """get first analysis task from flaw data"""
        for bz_id in flaw_data["blocks"]:
            # we only care for product and assignee
            bug = self.get_bug_data(bz_id, include_fields=["assigned_to", "product"])
            if bug["product"] == ANALYSIS_TASK_PRODUCT:
                return bug

        return None

    def sync_flaw(self, flaw_id):
        """fetch-convert-save flaw with give Bugzilla ID"""
        # 1) fetch flaw data
        flaw_data = self.get_bug_data(flaw_id)
        flaw_comments = self.get_bug_comments(flaw_id)
        flaw_history = self.get_bug_history(flaw_id)
        flaw_task = self.get_flaw_task(flaw_data)
        flaw_bz_trackers = self.get_flaw_bz_trackers(flaw_data)
        flaw_jira_trackers = self.get_flaw_jira_trackers(flaw_data)
        nvd_cvss = NVDQuerier.nvd_cvss()

        # 2) convert flaw data to Django models
        fbc = FlawBugConvertor(
            flaw_data,
            flaw_comments,
            flaw_history,
            flaw_task,
            flaw_bz_trackers,
            flaw_jira_trackers,
            nvd_cvss,
        )
        flaws = fbc.flaws
        # TODO store errors

        # 3) save Django models
        for flaw in flaws:
            self.save(flaw)

    def collect(self):
        """
        collector run handler
        every run we sync one batch of flaws - or possibly less if already in sync
        initially we start with the most historical flaws and proceed chronoligically
        until the flaw data are complete and then periodically sync the modified flaws
        every run starts where the previous one finished
        """
        successes = []
        failures = []

        # remember time before BZ query so we do not miss
        # anything starting the next batch from it
        start_dt = timezone.now()

        flaw_ids = self.get_batch()

        # TODO good candidate for parallelizing
        for flaw_id, _ in flaw_ids:
            logger.debug(f"Fetching flaw with Bugzilla ID {flaw_id}")

            try:
                self.sync_flaw(flaw_id)
                successes.append(flaw_id)

            except Exception as e:
                # TODO just for testing and should be removed
                if "No CVE ID found in Bugzilla alias" in str(e):
                    continue
                logger.exception(f"Bugzilla flaw bug {flaw_id} import error: {str(e)}")
                failures.append(flaw_id)
                # TODO store error

        # when not enough data we have fetched everything
        # and later when already complete we stay complete
        complete = bool(self.is_complete or len(flaw_ids) < self.BATCH_SIZE)
        # last updated time of the last flaw is the new updated until
        # unless there were no changes when it is the start of the sync
        new_updated_until_dt = flaw_ids[-1][1] if flaw_ids else start_dt

        logger.info(f"{self.name} is updated until {new_updated_until_dt}")
        logger.debug(f"{self.name} data are{'' if complete else ' not'} complete")

        self.store(complete=complete, updated_until_dt=new_updated_until_dt)

        msg = f"{self.name} is updated until {new_updated_until_dt}:"
        msg += f" Successfully fetched: {', '.join(successes)}." if successes else ""
        msg += f" Unsuccessfully fetched: {', '.join(failures)}." if failures else ""
        msg += " Nothing new to fetch." if not flaw_ids else ""
        return msg


class BzTrackerCollector(Collector, BugzillaQuerier):

    # version 0.0.1 of OSIDB was released on January 21st 2022
    BEGINNING = timezone.datetime(2022, 1, 21, tzinfo=timezone.get_current_timezone())
    BATCH_SIZE = 100
    BATCH_PERIOD = relativedelta(months=1)

    def query_all_trackers(self):
        """
        Returns the basic query filters to get the list of relevant tracker bugs.
        """
        return {
            "keywords": ["SecurityTracking"],
            # means "Bug contains any of the specified keywords", essentially
            # a set intersection.
            "keywords_type": "anywords",
            "query_format": "advanced",
        }

    def get_tracker_ids(self, updated_after=None, updated_before=None):
        return sorted(
            self.run_query(
                self.query_last_updated(
                    self.query_all_trackers(),
                    updated_after,
                    updated_before,
                ),
            ),
            key=lambda x: x[1],  # sort by ascending last change time
        )

    def get_batch(self):
        """
        Get the next batch of Bugzilla Tracker bugs.
        """
        period_start = self.metadata.updated_until_dt or self.BEGINNING
        period_end = period_start + self.BATCH_PERIOD

        tracker_ids = self.get_tracker_ids(period_start, period_end)
        while len(tracker_ids) < self.BATCH_SIZE and period_end < timezone.now():
            # TODO: can this be optimized to avoid doing "useless" requests?
            period_end += self.BATCH_PERIOD
            tracker_ids = self.get_tracker_ids(period_start, period_end)

        return tracker_ids

    def sync_tracker(self, tracker_id):
        """
        Fetch, convert and save a bugzilla tracker from a given Bugzilla ID.
        """
        tracker_data = self.get_bug_data(tracker_id)
        # not passing an affect explicitly during periodic sync should be fine
        # - case A:
        #   tracker is new, will be created from FlawCollector with correct affect,
        #   if for some reason this doesn't happen and the periodic collector creates
        #   the tracker first, FlawCollector should eventually create it and add the
        #   affect as a side-effect of create_tracker().
        # - case B:
        #   tracker exists, will be updated and passing affect=None will not change
        #   the set of affects.
        # - case C:
        #   tracker exists and affect has been removed, in which case the tracker is
        #   orphaned which isn't ideal but isn't the end of the world either.
        # - case D:
        #   tracker is deleted? not sure if that can happen anyway as I would imagine
        #   that the tracker would not be deleted but corrected and/or set to a
        #   specific state/resolution, but if it truly is deleted then it's currently
        #   not handled.
        TrackerBugConvertor(tracker_data, Tracker.TrackerType.BZ).convert().save(
            auto_timestamps=False
        )

    def collect(self):
        successes = []
        failures = []

        start_dt = timezone.now()

        tracker_ids = self.get_batch()
        for tracker_id, _ in tracker_ids:
            logger.debug(f"Fetching Bugzilla tracker with ID {tracker_id}")

            try:
                self.sync_tracker(tracker_id)
                successes.append(tracker_id)
            except Exception as e:
                logger.exception(
                    f"Bugzilla tracker bug with id {tracker_id} import error: {str(e)}"
                )
                failures.append(tracker_id)

        complete = bool(self.is_complete or len(tracker_ids) < self.BATCH_SIZE)
        new_updated_until_dt = tracker_ids[-1][1] if tracker_ids else start_dt

        logger.info(f"{self.name} is updated until {new_updated_until_dt}")
        logger.debug(f"{self.name} data are{'' if complete else ' not'} complete")

        self.store(complete=complete, updated_until_dt=new_updated_until_dt)

        msg = f"{self.name} is updated until {new_updated_until_dt}:"
        msg += f" Successfully fetched: {', '.join(successes)}." if successes else ""
        msg += f" Unsuccessfully fetched: {', '.join(failures)}." if failures else ""
        msg += " Nothing new to fetch." if not tracker_ids else ""
        return msg
