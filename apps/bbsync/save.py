from datetime import datetime

import requests
from django.utils.timezone import make_aware

from collectors.bzimport.collectors import BugzillaQuerier, FlawCollector
from osidb.constants import DATETIME_FMT
from osidb.exceptions import DataInconsistencyException
from osidb.models import Flaw

from .constants import SYNC_FLAWS_TO_BZ_ASYNCHRONOUSLY
from .exceptions import UnsaveableFlawError
from .query import FlawBugzillaQueryBuilder


class BugzillaSaver(BugzillaQuerier):
    """
    Bugzilla bug save handler underlying model instance
    the instance validity is assumed and not checked
    """

    @property
    def model(self):
        """
        instance model class getter
        needs to be defined in the subclasses
        """
        raise NotImplementedError

    @property
    def query_builder(self):
        """
        query builder class getter
        needs to be defined in the subclasses
        """
        raise NotImplementedError

    def __init__(self, instance, bz_api_key):
        """
        init stuff
        """
        super().__init__()
        self.instance = instance
        # substitute the default service Bugzilla API key
        # so the resulting Bugzilla audit log corresponds
        # to the acutal user requesting the operation
        self._bz_api_key = bz_api_key

    def save(self):
        """
        generic save serving as class entry point
        which calls create or update handler to continue
        returns an updated instance (without saving)
        """
        return self.create() if self.instance.bz_id is None else self.update()

    def create(self):
        """
        create a bug underlying the model instance in Bugilla
        """
        bugzilla_query_builder = self.query_builder(self.instance)
        response = self.bz_conn.createbug(bugzilla_query_builder.query)
        self.instance.bz_id = str(response.id)
        if isinstance(self.instance, Flaw) and SYNC_FLAWS_TO_BZ_ASYNCHRONOUSLY:
            # update the meta_attr according to the changes
            # since in the async mode we do not fetch them
            self.model.objects.filter(uuid=self.instance.uuid).update(
                meta_attr=bugzilla_query_builder.meta_attr
            )
        return self.instance

    def update(self):
        """
        update a bug underlying the model instance in Bugilla
        """
        # switch of sync/async processing of flaws
        if not isinstance(self.instance, Flaw) or not SYNC_FLAWS_TO_BZ_ASYNCHRONOUSLY:
            try:
                bugzilla_query_builder = self.query_builder(self.instance)
                self.check_collisions()  # check for collisions right before the update
            except DataInconsistencyException:
                if not isinstance(self.instance, Flaw):
                    raise

                # to mitigate user discomfort and also possible service errors
                # we handle the flaws more gently here attempting to resync
                flaw_collector = FlawCollector()
                flaw_collector.sync_flaw(self.instance.bz_id)

                # resync from the DB and repeat the query building
                self.instance.meta_attr = Flaw.objects.get(
                    pk=self.instance.pk
                ).meta_attr  # update metadata after refresh
                bugzilla_query_builder = self.query_builder(self.instance)
                self.check_collisions()  # if still colliding then something is very wrong

            try:
                self.bz_conn.update_bugs(
                    [self.instance.bz_id], bugzilla_query_builder.query
                )
            except requests.exceptions.HTTPError as e:
                # this is a heuristic at best, we know that the data we submit to
                # bugzilla has already been validated and are pretty sure that the
                # error is not due to the request being malformed, but it could be.
                # bugzilla returns a 400 error on concurrent updates even though
                # this is not the client's fault, and the HTTPError bubbled up
                # by requests / python-bugzilla doesn't contain the response
                # embedded into it, so all we can do is a string comparison.
                if "400" in str(e):
                    raise DataInconsistencyException(
                        "Failed to write back to Bugzilla, this is likely due to a "
                        "concurrent update which Bugzilla does not support, "
                        "try again later."
                    ) from e

                # reraise otherwise
                raise e
            return self.instance
        else:
            bugzilla_query_builder = self.query_builder(self.instance)
            self.bz_conn.update_bugs(
                [self.instance.bz_id], bugzilla_query_builder.query
            )
            # update the meta_attr according to the changes
            # since in the async mode we do not fetch them
            self.model.objects.filter(uuid=self.instance.uuid).update(
                meta_attr=bugzilla_query_builder.meta_attr
            )
            return self.instance

    def check_collisions(self):
        """
        one last preventative check that Bugzilla last_change_time
        really corresponds to the stored one so there was no collision
        """
        if self.actual_last_change != self.stored_last_change:
            raise DataInconsistencyException(
                "Save operation based on an outdated model instance: "
                f"Bugzilla last change time {self.actual_last_change} "
                f"differs from OSIDB {self.stored_last_change}. "
                "You need to wait a minute for the data refresh."
            )

    @property
    def actual_last_change(self):
        """
        retrieve the actual last change timestamp from Bugzilla
        """
        return make_aware(
            datetime.strptime(
                self.get_bug_data(
                    self.instance.bz_id, include_fields=["last_change_time"]
                )["last_change_time"],
                DATETIME_FMT,
            )
        )

    @property
    def stored_last_change(self):
        """
        retrieve the stored last change timestamp from DB
        """
        last_change_time = (
            self.instance.meta_attr["last_change_time"]
            if "last_change_time" in self.instance.meta_attr
            else self.instance.meta_attr["updated_dt"]
        )
        return make_aware(datetime.strptime(last_change_time, DATETIME_FMT))


class FlawBugzillaSaver(BugzillaSaver):
    """
    Bugzilla flaw bug save handler
    """

    @property
    def flaw(self):
        """
        concrete name shortcut
        """
        return self.instance

    @property
    def model(self):
        """
        Flaw model class getter
        """
        return Flaw

    @property
    def query_builder(self):
        """
        query builder class getter
        """
        return FlawBugzillaQueryBuilder

    def update(self):
        """
        update flaw in Bugzilla
        """
        # TODO flaws with multiple CVEs introduce a paradox behavior
        # when modifying a flaw the way that the CVE ID is removed as
        # in OSIDB it basically results in a flaw removal
        # so let us restrict it for now - should be rare
        if (
            self.model.objects.filter(meta_attr__bz_id=self.flaw.bz_id).count() > 1
            and not self.flaw.cve_id
        ):
            raise UnsaveableFlawError(
                "Unable to remove a CVE ID from a flaw with multiple CVEs "
                "due to an ambigous N to 1 OSIDB to Buzilla flaw mapping"
            )

        return super().update()
