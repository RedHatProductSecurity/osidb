import json
from itertools import chain

from collectors.bzimport.constants import ANALYSIS_TASK_PRODUCT, BZ_DT_FMT_HISTORY
from osidb.models import Flaw, FlawImpact, PsModule, Tracker

DATE_FMT = "%Y-%m-%d"
# these two time formats are the same
# thus spare us defining it again
DATETIME_FMT = BZ_DT_FMT_HISTORY


class SRTNotesBuilder:
    """
    Bugzilla flaw bug SRT notes field JSON content builder
    """

    def __init__(self, flaw, old_flaw=None):
        """
        init stuff
        parametr old_flaw is optional as there is no old flaw on creation
        and if not set we consider the query to be a create query
        """
        self.flaw = flaw
        self.old_flaw = old_flaw
        self._json = None
        self._original_keys = []

    @property
    def content(self):
        """
        string content getter shorcut
        """
        if self._json is None:
            self.generate()

        return json.dumps(self._json)

    def add_conditionally(self, key, value, empty_value=None):
        """
        conditionally add the value to the SRT notes field
        unless it is empty and was not originally present

        this is to make less noise in Bugzilla history
        """
        # value was there already
        if key in self._original_keys:
            self._json[key] = value

        # some attributes have special values to denote emptyness
        # for example empty impact has string value of "none"
        elif empty_value is not None:
            if value != empty_value:
                self._json[key] = value

        # some values are empty when their boolean conversion is False
        # for example arrays or strings or timestamps
        elif value:
            self._json[key] = value

    def generate(self):
        """
        generate json content
        """
        self.restore_original()
        self.generate_affects()
        self.generate_date("unembargo_dt", "public")
        self.generate_date("reported_dt", "reported")
        self.generate_impact()
        self.generate_jira_trackers()
        # TODO the references are not yet fully implemented in OSIDB
        # this requirement is trackerd in OSIDB-71 and when fulfilled
        # we need to implement generate_references accordingly
        self.generate_source()
        self.generate_string("cvss2", "cvss2")
        self.generate_string("cvss3", "cvss3")
        # TODO the CVSS comments are not yet supported in OSIDB and tracked as part of OSIDB-377
        # we need to implement their SRT notes generator afterwards and probably modify
        # the existing CVSS into SRT notes generation too
        self.generate_string("cwe_id", "cwe")
        # TODO mitigation field is not yet supported in OSIDB
        # this requirement is tracked in when OSIDB-584 and when fulfilled
        # we need to implement its proper SRT notes generator too while
        # it should probably be enough to just uncomment the next line
        # self.generate_string("mitigation", "mitigation")
        self.generate_string("statement", "statement")

    def generate_affects(self):
        """
        generate array of affects to SRT notes
        """
        self.add_conditionally(
            "affects",
            [
                {
                    "ps_module": affect.ps_module,
                    "ps_component": affect.ps_component,
                    "affectedness": affect.affectedness.lower() or None,
                    "resolution": affect.resolution.lower() or None,
                    # there is an interesting fact that the impact may be null or none
                    # while these two values hold the same information (empty impact)
                    # so let us prefer null which may cause some unexpected rewrites
                    # from none to null but this can be considered as data fixes
                    "impact": affect.impact.lower() or None,
                    "cvss2": affect.cvss2 or None,
                    "cvss3": affect.cvss3 or None,
                }
                for affect in self.flaw.affects.all()
            ],
        )

    def generate_date(self, flaw_attribute, srtnotes_attribute):
        """
        generate given date attribute

        it can be either date or datetime so we should check the old
        value and preserve the format when the value does not change
        """
        date_value = getattr(self.flaw, flaw_attribute)
        if not date_value:
            self.add_conditionally(srtnotes_attribute, None)
            return

        date_str = date_value.strftime(DATE_FMT)
        if (
            srtnotes_attribute in self._original_keys
            and self.old_flaw
            and date_value == getattr(self.old_flaw, flaw_attribute)
            and self._json[srtnotes_attribute] == date_str
        ):
            # we prefer datetime format but if there was just date format
            # before and the value does not change we keep the old format
            pass

        else:
            self._json[srtnotes_attribute] = date_value.strftime(DATETIME_FMT)

    def generate_impact(self):
        """
        generate impact attribute
        """
        impact = "none" if not self.flaw.impact else self.flaw.impact.lower()
        self.add_conditionally("impact", impact, empty_value="none")

    def generate_jira_trackers(self):
        """
        generate array of Jira tracker identifier pairs
        consisting of BTS name being Jira instance identifier
        and Jira issue key in given Jira instance
        """
        self.add_conditionally(
            "jira_trackers",
            [
                # BTS name is always jboss which is the
                # historical naming of the only Jira instance we use
                {"bts_name": "jboss", "key": tracker.external_system_id}
                for affect in self.flaw.affects.all()
                for tracker in affect.trackers.filter(type=Tracker.TrackerType.JIRA)
            ],
        )

    def generate_source(self):
        """
        generate source attribute
        """
        # HW_VENDOR is represented as hw-vendor in data
        source = self.flaw.source.lower().replace("_", "-")
        source = source if source else None
        self.add_conditionally("source", source)

    def generate_string(self, flaw_attribute, srtnotes_attribute):
        """
        generate given string attribute
        generic generator for string attributes with no special handling
        """
        self.add_conditionally(
            srtnotes_attribute, getattr(self.flaw, flaw_attribute) or None
        )

    def restore_original(self):
        """
        restore the original SRT notes attributes
        this ensures that we preserve potential unknown attributes intact
        """
        srtnotes = self.flaw.meta_attr.get("original_srtnotes")
        self._json = json.loads(srtnotes) if srtnotes else {}
        self._original_keys = list(self._json.keys())


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
        self.generate_srt_notes()
        # TODO placeholder + has different groups
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

    # Bugzilla groups allowed to be set for Bugzilla Security Response product
    # https://bugzilla.redhat.com/editproducts.cgi?action=edit&product=Security%20Response
    # TODO should be ideally synced so they are kept up-to-date but let us start simple
    ALLOWED_GROUPS = [
        "cinco",
        "private",
        "qe_staff",
        "redhat",
        "secalert",
        "secalert_entry",
        "security",
        "team ocp_embargoes",
    ]
    EMBARGOED_GROUPS = ["qe_staff", "security"]

    def _standardize_embargoed_groups(self, groups):
        """
        combine groups with default embargoed but make sure all
        of them are allowed plus always remove redhat group

        this serves as a safegourd ensuring that all embargoed flaws
        have the embargoed groups and never the redhat group plus we
        ignore groups which are not allowed to be assigned to flaws
        in case anyone put them in the product definitions
        """
        return list(
            ((set(groups) | set(self.EMBARGOED_GROUPS)) & set(self.ALLOWED_GROUPS))
            - {"redhat"}
        )

    def _lists2diffs(self, new_list, old_list):
        """
        take the new and the old list and return
        the differences to be added and removed
        """
        to_add = list(set(new_list) - set(old_list))
        to_remove = list(set(old_list) - set(new_list))
        return to_add, to_remove

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

            groups = self._standardize_embargoed_groups(module_groups)

        # TODO we do not account for placeholder flaws

        # on creation we provide a list of groups
        if self.creation:
            self._query["groups"] = groups

        # otherwise we provide the differences
        else:
            old_groups = json.loads(self.old_flaw.meta_attr.get("groups", "[]"))
            add_groups, remove_groups = self._lists2diffs(groups, old_groups)
            self._query["groups"] = {
                "add": add_groups,
                "remove": remove_groups,
            }

    def generate_deadline(self):
        """
        generate query for Bugzilla deadline
        """
        if self.flaw.embargoed:
            if self.flaw.unembargo_dt:
                self._query["deadline"] = self.flaw.unembargo_dt.strftime(DATE_FMT)

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

    def generate_srt_notes(self):
        """
        generate query for SRT notes
        """
        srt_notes_builder = SRTNotesBuilder(self.flaw, self.old_flaw)
        self._query["cf_srtnotes"] = srt_notes_builder.content
