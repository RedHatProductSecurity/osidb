from datetime import datetime

from django.utils.timezone import make_aware

from collectors.bzimport.collectors import BugzillaQuerier
from osidb.constants import DATETIME_FMT
from osidb.exceptions import DataInconsistencyException
from osidb.models import Flaw

from .exceptions import UnsaveableFlawError
from .query import BugzillaQueryBuilder


class BugzillaSaver(BugzillaQuerier):
    """
    Bugzilla flaw bug save handler
    flaw validity is assumed and not checked
    """

    def __init__(self, flaw, bz_api_key):
        """
        init stuff
        """
        self.flaw = flaw
        # substitute the default service Bugzilla API key
        # so the resulting Bugzilla audit log corresponds
        # to the acutal user requesting the operation
        self._bz_api_key = bz_api_key

    def save(self):
        """
        generic save serving as class entry point
        which calls create or update handler to continue
        returns an updated flaw instance (without saving)
        """
        return self.create() if self.flaw.bz_id is None else self.update()

    def create(self):
        """
        create flaw in Bugilla
        """
        bugzilla_query_builder = BugzillaQueryBuilder(self.flaw)
        response = self.bz_conn.createbug(bugzilla_query_builder.query)
        self.flaw.meta_attr["bz_id"] = response.id
        return self.flaw

    def update(self):
        """
        update flaw in Bugzilla
        """
        # TODO flaws with multiple CVEs introduce a paradox behavior
        # when modifying a flaw the way that the CVE ID is removed as
        # in OSIDB it basically results in a flaw removal
        # so let us restrict it for now - should be rare
        if (
            Flaw.objects.filter(meta_attr__bz_id=self.flaw.bz_id).count() > 1
            and not self.flaw.cve_id
        ):
            raise UnsaveableFlawError(
                "Unable to remove a CVE ID from a flaw with multiple CVEs "
                "due to an ambigous N to 1 OSIDB to Buzilla flaw mapping"
            )

        old_flaw = Flaw.objects.get(uuid=self.flaw.uuid)
        bugzilla_query_builder = BugzillaQueryBuilder(self.flaw, old_flaw)
        self.check_collisions()  # check for collisions right before the update
        self.bz_conn.update_bugs([self.flaw.bz_id], bugzilla_query_builder.query)
        return self.flaw

    def check_collisions(self):
        """
        one last preventative check that Bugzilla last_change_time
        really corresponds to the stored one so there was no collision
        """
        if self.actual_last_chante != self.stored_last_change:
            raise DataInconsistencyException(
                "Save operation based on an outdated model instance"
            )

    @property
    def actual_last_chante(self):
        """
        retrieve the actual last change timestamp from Bugzilla
        """
        return make_aware(
            datetime.strptime(
                self.get_bug_data(self.flaw.bz_id, include_fields=["last_change_time"])[
                    "last_change_time"
                ],
                DATETIME_FMT,
            )
        )

    @property
    def stored_last_change(self):
        """
        retrive the stored last change timestamp from DB
        """
        return make_aware(
            datetime.strptime(self.flaw.meta_attr["last_change_time"], DATETIME_FMT)
        )
