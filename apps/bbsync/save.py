from collectors.bzimport.collectors import BugzillaConnector
from osidb.models import Flaw

from .exceptions import UnsaveableFlawError
from .query import BugzillaQueryBuilder


class BugzillaSaver(BugzillaConnector):
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
        self.bz_conn.update_bugs([self.flaw.bz_id], bugzilla_query_builder.query)
        return self.flaw
