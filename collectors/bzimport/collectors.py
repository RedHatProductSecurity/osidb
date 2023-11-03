"""
Bugzilla collector
"""
import json
import time
from typing import Union

import bugzilla
import requests
from bugzilla.base import Bugzilla
from celery.utils.log import get_task_logger
from dateutil.relativedelta import relativedelta
from django.db import transaction
from django.utils import timezone
from joblib import Parallel, delayed

from apps.bbsync.models import BugzillaComponent, BugzillaProduct
from collectors.bzimport.convertors import BugzillaTrackerConvertor, FlawConvertor
from collectors.bzimport.srtnotes_parser import parse_cf_srtnotes
from collectors.framework.models import Collector
from collectors.jiraffe.core import JiraQuerier
from osidb.models import Flaw, PsModule

from .constants import (
    ANALYSIS_TASK_PRODUCT,
    BZ_API_KEY,
    BZ_DT_FMT,
    BZ_URL,
    PARALLEL_THREADS,
)
from .exceptions import RecoverableBZImportException

logger = get_task_logger(__name__)


class BugzillaConnector:
    """Bugzilla connection handler"""

    # by default use the service key of the running instance
    # but allow the key substitution in the child classes
    _bz_api_key = BZ_API_KEY
    _bz_conn = None

    def create_bz_conn(self) -> Bugzilla:
        """create Bugzilla connection"""
        bz_conn = bugzilla.Bugzilla(url=BZ_URL, api_key=self.api_key, force_rest=True)
        if not bz_conn.logged_in:
            raise RecoverableBZImportException("Cannot access Bugzilla")
        return bz_conn

    @property
    def api_key(self) -> str:
        """
        Bugzilla API key getter
        """
        return self._bz_api_key

    @property
    def bz_conn(self) -> Bugzilla:
        """get Bugzilla connection"""
        if self._bz_conn is None:
            self._bz_conn = self.create_bz_conn()

        return self._bz_conn


class BugzillaQuerier(BugzillaConnector):
    """Bugzilla query handler"""

    # This is the max amount of records to be returned by the BZ API per
    # request, the default is 20 and the maximum allowed is 1000 for the
    # specific Bugzilla instance that we use. However, 1000 is a lot and
    # can result in 503 errors which can be potentially crippling for
    # collectors and make them stuck, so here we choose a sensible limit
    # that allows us to fetch a lot more than the default without being
    # too greedy.
    # TODO: Set up a mechanism to lower the LIMIT based on 503 error returned
    BZ_API_LIMIT = 100

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
        """extend query to override default limit with BZ_API_LIMIT"""
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

    def _run_query(self, query):
        try:
            return self.bz_conn.query(query)
        except requests.exceptions.ConnectionError as e:
            r: requests.PreparedRequest = e.request
            # sanitize the headers
            r.headers.pop("Authorization", None)
            r.headers.pop("Cookie", None)

            logger.error(
                f"\n--------------------------------------------\n"
                f"Method: {r.method}\n"
                f"URL: {r.url}\n"
                f"Headers: {r.headers}\n"
                f"Body: {r.body}\n"
                f"--------------------------------------------"
            )
            raise

    def run_query(self, query):
        """
        query for Bugzilla bugs
        returns IDs and last change times as list of tupples
        """
        query = self.query_maximum(query)
        updated_query = query
        bugs = []

        logger.debug(
            "Running Bugzilla query with the following parameters: " f"{updated_query}"
        )

        while True:
            query_result = self._run_query(updated_query)
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

    ####################
    # METADATA QUERIES #
    ####################

    def get_product_with_components(self, name):
        """
        getter shortcut for a given Bugzilla product
        together with the list of its Bugzilla components
        """
        products = self.bz_conn.product_get(
            names=[name], include_fields=["name", "components"]
        )
        return products[0] if products else None


# TODO tzinfo should be set implicitly but my current
# attempts do not work - leaving explicit for now
TIMEZONE = timezone.get_current_timezone()


class FlawCollector(Collector, BugzillaQuerier, JiraQuerier):
    """Bugzilla flaw collector"""

    # date before the first flaw was created
    BEGINNING = timezone.datetime(2000, 1, 1, tzinfo=TIMEZONE)

    # this should be considered the minimum amount of flaws to be synced
    # per collector run and not a hard limit per batch, as each batch will
    # most likely contain more than this, but not less unless it's the last run
    BATCH_SIZE = 100

    # the list of Bugzilla flaw data migrations
    # as they mean high numbers of flaw changes clustered
    # into small time periods requiring special handling
    MIGRATIONS = [
        # there was a huge and very dense data migration between
        # 2019-09-29 12:19:32 - 2019-09-29 15:37:58
        # so we prevent very long query going by minute
        {
            "start": timezone.datetime(2019, 9, 29, 12, 19, tzinfo=TIMEZONE),
            "end": timezone.datetime(2019, 9, 29, 15, 38, tzinfo=TIMEZONE),
            "step": relativedelta(minutes=1),
        },
        # there was a huge data migration between
        # 2021-02-16 17:08:37 - 2021-02-17 08:30:43
        # so we prevent very large batches going by ten minutes
        {
            "start": timezone.datetime(2021, 2, 16, 17, 8, tzinfo=TIMEZONE),
            "end": timezone.datetime(2021, 2, 17, 8, 30, tzinfo=TIMEZONE),
            "step": relativedelta(minutes=10),
        },
        # there was a large data migration
        # (probably followup of previous one) between
        # 2021-02-23 13:37:22 - 2021-02-26 17:19:23
        # so we prevent large batches going by an hour
        {
            "start": timezone.datetime(2021, 2, 23, 13, 37, tzinfo=TIMEZONE),
            "end": timezone.datetime(2021, 2, 26, 17, 19, tzinfo=TIMEZONE),
            "step": relativedelta(hours=1),
        },
        # migration of old style acks to SRT notes
        # https://issues.redhat.com/browse/OSIDB-275
        # 2023-05-11 12:19 UTC – 2023-05-13 02:03 UTC
        # so we prevent large batches going by 5 hours
        {
            "start": timezone.datetime(2023, 5, 11, 12, 19, tzinfo=TIMEZONE),
            "end": timezone.datetime(2023, 5, 13, 2, 3, tzinfo=TIMEZONE),
            "step": relativedelta(hours=5),
        },
        # migration reassigning flaws to nobody@redhat.com
        # after security-response-team@redhat.com disabling
        # 2023-07-07 08:25 UTC – 2023-07-07 08:40 UTC
        # so we prevent large batches going by 3 minutes
        {
            "start": timezone.datetime(2023, 7, 7, 8, 25, tzinfo=TIMEZONE),
            "end": timezone.datetime(2023, 7, 7, 8, 40, tzinfo=TIMEZONE),
            "step": relativedelta(minutes=3),
        },
    ]

    def end_period_heuristic(self, period_start):
        """
        very simple heuristic to optimize the batch period
        basically in the past there are a few flaws every year
        but recently there is a lot of them every week
        and there some problematic data migrations
        """
        if period_start < timezone.datetime(2010, 1, 1, tzinfo=TIMEZONE):
            return period_start + relativedelta(years=5)

        if period_start < timezone.datetime(2018, 1, 1, tzinfo=TIMEZONE):
            return period_start + relativedelta(years=1)

        # then we have more regularly scattered data
        # and the possible future date is no problem
        # so we can use it for the periodic sync too
        period_end = period_start + relativedelta(months=1)

        # but we have to account for the periods of data migrations
        for migration in self.MIGRATIONS:
            if period_start < migration["start"] and period_end > migration["start"]:
                return migration["start"]

            if period_start >= migration["start"] and period_start < migration["end"]:
                return period_start + migration["step"]

        return period_end

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
        """
        get Bugzilla trackers from flaw data

        catch exceptions individually so we do
        not fail everything for a single issue
        """
        bz_trackers = []

        for bz_id in flaw_data["depends_on"]:
            try:
                bug = self.get_bug_data(bz_id)
                # security tracking Bugzilla bug has always SecurityTracking keyword
                # there may be any other non-tracker bugs in the depends_on field
                if "SecurityTracking" in bug["keywords"]:
                    bz_trackers.append(bug)
            except Exception as e:
                logger.exception(
                    f"Bugzilla flaw bug {flaw_data['id']} tracker import error: {str(e)}"
                )
                # TODO store errors

        return bz_trackers

    def get_flaw_jira_trackers(self, flaw_data: dict) -> list:
        """
        get Jira trackers from flaw data

        catch exceptions individually so we do
        not fail everything for a single issue
        """
        jira_trackers = []

        for jira_id in self.get_flaw_jira_tracker_ids(flaw_data):
            try:
                jira_trackers.append(self.get_issue(jira_id))
            except Exception as e:
                logger.exception(
                    f"Bugzilla flaw bug {flaw_data['id']} tracker import error: {str(e)}"
                )
                # TODO store errors

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
            try:
                bug = self.get_bug_data(
                    bz_id, include_fields=["assigned_to", "product"]
                )
            except IndexError:
                # some related bugs which are no tasks so not interesting may have restricted access
                # more strict than just security group and the fetching then results in IndexError
                # - does not seem as a correct handling from python-bugzilla side
                # we can simply skip these
                continue

            if bug["product"] == ANALYSIS_TASK_PRODUCT:
                return bug

        return None

    def sync_flaw(self, flaw_id):
        """fetch-convert-save flaw with give Bugzilla ID"""
        # 1A) fetch flaw data
        try:
            flaw_data = self.get_bug_data(flaw_id)
            flaw_comments = self.get_bug_comments(flaw_id)
            flaw_history = self.get_bug_history(flaw_id)
            flaw_task = self.get_flaw_task(flaw_data)
        except Exception as e:
            # fetching the data is prone to transient failures which are recoverable
            # while the permanent issues are not expected at this stage of flaw sync
            raise RecoverableBZImportException(
                f"Temporary exception raised while fetching flaw data: {flaw_id}"
            ) from e

        # 1B) fetch tracker data

        flaw_bz_trackers = self.get_flaw_bz_trackers(flaw_data)
        flaw_jira_trackers = self.get_flaw_jira_trackers(flaw_data)

        # 2) convert flaw data to Django models
        fbc = FlawConvertor(
            flaw_data,
            flaw_comments,
            flaw_history,
            flaw_task,
            flaw_bz_trackers,
            flaw_jira_trackers,
        )
        flaws = fbc.flaws
        # TODO store errors

        # 3) save Django models
        for flaw in flaws:
            self.save(flaw)

    def collect(self, batch=None):
        """
        collector run handler
        every run we sync one batch of flaws - or possibly less if already in sync
        initially we start with the most historical flaws and proceed chronoligically
        until the flaw data are complete and then periodically sync the modified flaws
        every run starts where the previous one finished

        alternatively you can specify a batch as the parameter - list of Bugzilla IDs
        then all updated until and completeness sugar is skipped
        """
        # remember time before BZ query so we do not miss
        # anything starting the next batch from it
        start_dt = timezone.now()

        flaw_ids = [(i, i) for i in batch] if batch is not None else self.get_batch()

        # collect data in parallel
        results = Parallel(n_jobs=PARALLEL_THREADS, prefer="threads")(
            delayed(self.collect_flaw)(flaw_id) for flaw_id, _ in flaw_ids
        )
        # process the results
        successes, failures = [success for success, _ in results if success], [
            failure for _, failure in results if failure
        ]

        # with specified batch we stop here
        if batch is not None:
            return

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

    def collect_flaw(self, flaw_id, total_retries=0):
        """
        collect flaw by the given ID
        return the success,failure pair
        """
        logger.debug(f"Fetching flaw with Bugzilla ID {flaw_id}")

        try:
            self.sync_flaw(flaw_id)
            return (flaw_id, None)

        except RecoverableBZImportException:
            # we will retry the same flaw with exponential backoff
            # as these failures can simply be due to rate-limiting.
            # NOTE: this is kinda hackish as we should be using celery's retry
            # mechanism.
            if total_retries < 5:
                time.sleep(60 * (2**total_retries))
                return self.collect_flaw(flaw_id, total_retries=total_retries + 1)
            # otherwise we fail the whole batch so it can be fully rerun
            raise

        except Exception as e:
            logger.exception(f"Bugzilla flaw bug {flaw_id} import error: {str(e)}")
            return (None, flaw_id)
            # TODO store error


class BugzillaTrackerCollector(Collector, BugzillaQuerier):

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
        BugzillaTrackerConvertor(tracker_data).convert().save(
            auto_timestamps=False, raise_validation_error=False
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


class MetadataCollector(Collector, BugzillaQuerier):
    """
    Bugzilla metadata collector
    to collect data on Bugzilla products and components
    """

    def collect(self):
        """
        collector run handler
        """
        start_dt = timezone.now()

        products = {}
        product_names = (
            # when fetching Fedora the connection often hangs (maybe to much data)
            # and we do not add CCs to the community stuff so we can ignore it
            PsModule.objects.exclude(ps_product__business_unit="Community")
            .filter(bts_name="bugzilla")
            .values_list("bts_key", flat=True)
            .distinct()
        )
        for product_name in product_names:
            # we need to fetch the products one by one or the connection hangs
            product = self.get_product_with_components(product_name)

            if product is None:
                continue

            products[product["name"]] = [
                {
                    "name": component["name"],
                    "default_owner": component["default_assigned_to"],
                    "default_cc": component["default_cc"],
                }
                for component in product["components"]
            ]

        self.update_metadata(products)

        self.store(updated_until_dt=start_dt)
        logger.info(f"{self.name} is updated until {start_dt}")
        return f"{self.name} is updated until {start_dt}: {len(product_names)} Bugzilla products' metadata fetched"

    @transaction.atomic
    def update_metadata(self, products):
        """
        remove old and store new Bugzilla metadata

        as we first remove the old data and only then save the new data it should
        happen as an atomic transaction to prevent some invalid midterm state
        """
        BugzillaProduct.objects.all().delete()
        BugzillaComponent.objects.all().delete()

        for product_name, components in products.items():
            product = BugzillaProduct(name=product_name)
            product.save()

            for component in components:
                BugzillaComponent(product=product, **component).save()
