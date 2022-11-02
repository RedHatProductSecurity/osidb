import json
from itertools import chain

from collectors.bzimport.constants import ANALYSIS_TASK_PRODUCT
from osidb.models import Flaw, FlawImpact, PsModule


class BugzillaQueryBuilder:
    """
    Bugzilla flaw bug query builder
    to generate general flaw save query

    https://bugzilla.redhat.com/docs/en/html/api/index.html
    """

    def __init__(self, flaw, old_flaw=None):
        """
        init stuff
        parametr old_flaw is optional as there is no old flaw on creation
        and if not set we consider the query to be a create query
        """
        self.flaw = flaw
        self.old_flaw = old_flaw
        self._query = None

    @property
    def query(self):
        """
        query getter shorcut
        """
        if self._query is None:
            self.generate()

        return self._query

    @property
    def creation(self):
        return self.old_flaw is None

    def generate(self):
        """
        generate query
        """
        self.generate_base()
        self.generate_unconditional()
        self.generate_description()
        self.generate_resolution()
        self.generate_alias()
        self.generate_keywords()
        self.generate_flags()
        self.generate_groups()
        self.generate_deadline()
        self.generate_cc()
        # TODO placeholder + has different groups
        # TODO SRT notes
        # TODO tracker links
        # TODO prestage eligable date - deprecate
        # TODO checklists
        # TODO fixed_in
        # TODO dupe_of
        # TODO cf_devel_whiteboard
        # TODO ARRAY_FIELDS_ON_CREATE = ("depends_on", "blocks", "cc", "groups", "keywords")
        # TODO auto-requires doc text on create

    def generate_base(self):
        """
        generate static base of the query
        """
        self._query = {
            "product": ANALYSIS_TASK_PRODUCT,
            "component": "vulnerability",
            "op_sys": "Linux",
            "platform": "All",
            "version": "unspecified",
        }

    IMPACT_TO_SEVERITY_PRIORITY = {
        FlawImpact.CRITICAL: "urgent",
        FlawImpact.IMPORTANT: "high",
        FlawImpact.MODERATE: "medium",
        FlawImpact.LOW: "low",
        FlawImpact.NOVALUE: "unspecified",
    }

    def generate_unconditional(self):
        """
        generate query attributes not requiring conditional processing
        """
        self._query["summary"] = self.flaw.title  # TODO handle prefixes
        self._query["cf_release_notes"] = self.flaw.summary
        self._query["status"] = self.flaw.state
        self._query["severity"] = self.IMPACT_TO_SEVERITY_PRIORITY[self.flaw.impact]
        self._query["priority"] = self.IMPACT_TO_SEVERITY_PRIORITY[self.flaw.impact]

    def generate_description(self):
        """
        generate query for flaw description on create
        """
        if self.creation:
            self._query["description"] = self.flaw.comments.first().text
            self._query["comment_is_private"] = False
            # TODO
            # self._query["comment_is_private"] = True if ... else False

    def generate_resolution(self):
        """
        generate resolution query
        if status is CLOSED
        """
        if self.flaw.state == Flaw.FlawState.CLOSED:
            self._query["resolution"] = self.flaw.resolution

    def generate_alias(self):
        """
        generate add or remove CVE alias query
        conditionally based on the changes and create|update
        """
        if self.creation:
            if self.flaw.cve_id is not None:
                # create query requires pure list
                self._query["alias"] = [self.flaw.cve_id]

        elif self.flaw.cve_id != self.old_flaw.cve_id:
            self._query["alias"] = {}

            if self.flaw.cve_id is not None:
                self._query["alias"]["add"] = [self.flaw.cve_id]

            if self.old_flaw.cve_id is not None:
                self._query["alias"]["remove"] = [self.old_flaw.cve_id]

    def generate_keywords(self):
        """
        generate keywords query based on creation|update
        """
        self._query["keywords"] = (
            ["Security"] if self.old_flaw is None else {"add": ["Security"]}
        )

    def generate_flags(self):
        """
        generate query for Bugzilla flags
        """
        self._query["flags"] = []
        # TODO needinfo and other flags
        # hightouch | hightouch-lite | nist_cvss_validation | requires_doc_text

    EMBARGOED_GROUPS = ["qe_staff", "security"]

    def generate_groups(self):
        """
        generate query for Bugzilla groups
        which control the access to the flaw

        there are three cases when the groups should be touched

        1) on flaw creation we want to set the groups to either
           embargoed with respect to the product definitions or empty

        2) on affectedness changes of an embargoed flaw we want to
           adjust the groups according to the new affectedness

        3) on flaw unembargo when we want to remove all the groups
        """
        groups = []

        if self.flaw.embargoed:
            # get names of all affected PS modules
            # we care for affects with trackers only
            module_names = [
                affect.ps_module
                for affect in self.flaw.affects.filter(trackers__isnull=False)
            ]
            # gat all embargoed groups of all affected PS modules
            module_groups = chain(
                *[
                    ps_module.bts_groups.get("embargoed", [])
                    for ps_module in PsModule.objects.filter(name__in=module_names)
                ]
            )

            # TODO standardize embargoed groups
            groups = module_groups

        # TODO we do not account for placeholder flaws

        # on creation we provide a list of groups
        if self.creation:
            self._query["groups"] = groups

        # otherwise we provide the differences
        else:
            old_groups = json.loads(self.old_flaw.meta_attr.get("groups", "[]"))
            # TODO generate the diffs for update query
            add_groups, remove_groups = groups, old_groups
            self._query["groups"] = {
                "add": add_groups,
                "remove": remove_groups,
            }

    DEADLINE_FORMAT = "%Y-%m-%d"

    def generate_deadline(self):
        """
        generate query for Bugzilla deadline
        """
        if self.flaw.embargoed:
            if self.flaw.unembargo_dt:
                self._query["deadline"] = self.flaw.unembargo_dt.strftime(
                    self.DEADLINE_FORMAT
                )

        # unembargo
        elif not self.creation and self.old_flaw.embargoed:
            self._query["deadline"] = ""

    def generate_cc(self):
        """
        generate query for CC list
        """
        # TODO now just empty CC list on creation
        # on update it is more complicated
        if self.creation:
            self._query["cc"] = []
