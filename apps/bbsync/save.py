from collectors.bzimport.collectors import BugzillaConnector
from osidb.models import Flaw

from .query import BugzillaQueryBuilder


class BugzillaSaver(BugzillaConnector):
    """
    Bugzilla flaw bug save handler
    flaw validity is assumed and not checked
    """

    class UnsaveableFlaw(Exception):
        """
        error caused by attempt to save a flaw which cannot be saved
        either by its nature or due to the current saver capabilities
        """

        pass

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
        # TODO flaws with multiple CVEs are non-trivial to update
        # and save back to Bugzilla so let us restrict this for now
        if Flaw.objects.filter(meta_attr__bz_id=self.flaw.bz_id).count() > 1:
            raise self.UnsaveableFlaw(
                "Unable to save a flaw with multiple CVEs to Bugzilla "
                "due to an ambigous N to 1 OSIDB to Buzilla flaw mapping"
            )

        old_flaw = Flaw.objects.get(uuid=self.flaw.uuid)
        bugzilla_query_builder = BugzillaQueryBuilder(self.flaw, old_flaw)
        self.bz_conn.update_bugs([self.flaw.bz_id], bugzilla_query_builder.query)
        return self.flaw
