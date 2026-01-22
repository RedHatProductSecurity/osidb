"""
Bugzilla collector
"""

from datetime import datetime, timedelta

import bugzilla
import requests
from bugzilla.base import Bugzilla
from celery.utils.log import get_task_logger
from dateutil.relativedelta import relativedelta
from django.db import transaction
from django.utils import timezone

from apps.bbsync.models import BugzillaComponent, BugzillaProduct
from collectors.bzimport.convertors import BugzillaTrackerConvertor
from collectors.framework.models import Collector
from osidb.models import Flaw, PsModule
from osidb.sync_manager import (
    BZTrackerDownloadManager,
)

from .constants import (
    BZ_API_KEY,
    BZ_DT_FMT,
    BZ_MAX_CONNECTION_AGE,
    BZ_URL,
)
from .exceptions import RecoverableBZImportException

logger = get_task_logger(__name__)


class BugzillaConnector:
    """Bugzilla connection handler"""

    # by default use the service key of the running instance
    # but allow the key substitution in the child classes
    _bz_api_key = BZ_API_KEY

    def __init__(self):
        self._bz_conn = None
        self._bz_conn_timestamp = None

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
        """
        Get Bugzilla connection

        Create a new connection if it does not exist. If BZ_MAX_CONNECTION_AGE is set and the
        connection is older, also create a new connection. Otherwise, reuse already created
        connection.
        """
        if self._bz_conn is None:
            self._bz_conn = self.create_bz_conn()
            self._bz_conn_timestamp = datetime.now()
            logger.info("New Bugzilla connection created, no previous connection")

        elif BZ_MAX_CONNECTION_AGE is not None:
            connection_age = datetime.now() - self._bz_conn_timestamp
            if connection_age > timedelta(seconds=int(BZ_MAX_CONNECTION_AGE)):
                self._bz_conn = self.create_bz_conn()
                self._bz_conn_timestamp = datetime.now()
                logger.info(
                    f"New Bugzilla connection created, previous age {connection_age}"
                )

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
            "component": ["vulnerability", "vulnerability-draft"],
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
            f"Running Bugzilla query with the following parameters: {updated_query}"
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


class BugzillaTrackerCollector(Collector):
    # according to the Bugzilla advanced search the longest non-updated
    # security trackers going chronologically were last updated in 2010
    BEGINNING = timezone.datetime(2010, 1, 1, tzinfo=timezone.get_current_timezone())
    BATCH_SIZE = 100
    BATCH_PERIOD = relativedelta(months=1)

    def __init__(self):
        super().__init__()
        self._bz_querier = None

    @property
    def bz_querier(self):
        if self._bz_querier is None:
            self._bz_querier = BugzillaQuerier()
        return self._bz_querier

    def free_queriers(self):
        self._bz_querier = None

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
            self.bz_querier.run_query(
                self.bz_querier.query_last_updated(
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
        tracker_data = self.bz_querier.get_bug_data(tracker_id)
        tracker = BugzillaTrackerConvertor(tracker_data).tracker
        if tracker:
            self.save(tracker)

    def collect(self):
        successes = []
        failures = []

        start_dt = timezone.now()

        BZTrackerDownloadManager.check_for_reschedules()

        tracker_ids = self.get_batch()
        for tracker_id, _ in tracker_ids:
            BZTrackerDownloadManager.schedule(tracker_id)
            successes.append(tracker_id)

        complete = bool(self.is_complete or len(tracker_ids) < self.BATCH_SIZE)
        new_updated_until_dt = tracker_ids[-1][1] if tracker_ids else start_dt

        logger.info(f"{self.name} is updated until {new_updated_until_dt}")
        logger.debug(f"{self.name} data are{'' if complete else ' not'} complete")

        self.store(complete=complete, updated_until_dt=new_updated_until_dt)

        # Remove querier objects and close unneeded connection when collector task is finished
        self.free_queriers()

        msg = f"{self.name} is updated until {new_updated_until_dt}:"
        msg += f" Successfully fetched: {', '.join(successes)}." if successes else ""
        msg += f" Unsuccessfully fetched: {', '.join(failures)}." if failures else ""
        msg += " Nothing new to fetch." if not tracker_ids else ""
        return msg


class MetadataCollector(Collector):
    """
    Bugzilla metadata collector
    to collect data on Bugzilla products and components
    """

    def __init__(self):
        super().__init__()
        self._bz_querier = None

    @property
    def bz_querier(self):
        if self._bz_querier is None:
            self._bz_querier = BugzillaQuerier()
        return self._bz_querier

    def free_queriers(self):
        self._bz_querier = None

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
            product = self.bz_querier.get_product_with_components(product_name)

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

        # Remove querier objects and close unneeded connection when collector task is finished
        self.free_queriers()

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
