import json
import re
from itertools import chain

from collectors.bzimport.constants import ANALYSIS_TASK_PRODUCT
from osidb.models import Flaw, FlawComment, FlawImpact, PsModule

from .cc import CCBuilder
from .constants import DATE_FMT
from .srtnotes import SRTNotesBuilder


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
        self.generate_summary()
        self.generate_description()
        self.generate_alias()
        self.generate_keywords()
        self.generate_flags()
        self.generate_groups()
        self.generate_deadline()
        self.generate_cc()
        self.generate_srt_notes()
        self.generate_comment()
        # TODO tracker links
        # TODO fixed_in
        # TODO dupe_of
        # TODO cf_devel_whiteboard
        # TODO ARRAY_FIELDS_ON_CREATE = ("depends_on", "blocks")
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
        self._query["cf_release_notes"] = self.flaw.summary
        self._query["severity"] = self.IMPACT_TO_SEVERITY_PRIORITY[self.flaw.impact]
        self._query["priority"] = self.IMPACT_TO_SEVERITY_PRIORITY[self.flaw.impact]

    def generate_summary(self):
        """
        generate query for flaw summary based on
        embargoed status | CVE IDs | component | title

        EMBARGOED CVE-2000-12345 CVE-2020-9999 culr: stack overflow

            * EMBARGOED prefix is conditional depending on embargoed status
            * then follows sorted list of CVE IDs of all flaws with the same Bugzilla ID
              which may be empty when no CVE ID was assigned
            * then follows the component and collon
            * then follows the title

        """

        def cve_id_comparator(cve_id):
            """
            comparator to sort CVE IDs by

                1) the year
                2) the sequence
            """
            digits = re.sub(r"[^0-9]", "", cve_id)
            # stress the value of the year above the sequence
            return int(digits[:4]) ** 2 + int(digits[4:])

        embargoed = "EMBARGOED " if self.flaw.is_embargoed else ""

        # 1) get all CVE IDs of flaws with the same Bugzilla ID
        #    (this is to cover the cases of multi-CVE flaws)
        #    except the one which is just being updated or created
        #    as the DB instance may differ from this change
        cve_ids = [
            f.cve_id
            for f in Flaw.objects.filter(meta_attr__bz_id=self.flaw.bz_id).exclude(
                uuid=self.flaw.uuid
            )
            # 2) add the CVE ID from the flaw being updated or created
        ] + [self.flaw.cve_id]
        # 3) filter out the empty CVE IDs
        #    there can be one in case we are removing the CVE ID
        cve_ids = [cve_id for cve_id in cve_ids if cve_id]
        # 4) filter out eventual duplicates | sort by CVE ID | stringify
        cve_ids = " ".join(sorted(list(set(cve_ids)), key=cve_id_comparator))
        # 5) add trailing space delimiter in case of non-empty CVE IDs
        cve_ids = cve_ids + " " if cve_ids else cve_ids

        component = self.flaw.component + ": " if self.flaw.component else ""
        self._query["summary"] = embargoed + cve_ids + component + self.flaw.title

    def generate_description(self):
        """
        generate query for flaw description on create
        """
        if self.creation:
            self._query["description"] = self.flaw.description
            self._query["comment_is_private"] = False

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

        if self.flaw.is_embargoed:
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
        if self.flaw.is_embargoed:
            if self.flaw.unembargo_dt:
                self._query["deadline"] = self.flaw.unembargo_dt.strftime(DATE_FMT)

        # unembargo
        elif not self.creation and self.old_flaw.embargoed:
            self._query["deadline"] = ""

    def generate_cc(self):
        """
        generate query for CC list
        """
        cc_builder = CCBuilder(self.flaw, self.old_flaw)
        add_cc, remove_cc = cc_builder.content

        if self.creation:
            self._query["cc"] = add_cc

        else:
            self._query["cc"] = {
                "add": add_cc,
                "remove": remove_cc,
            }

    def generate_srt_notes(self):
        """
        generate query for SRT notes
        """
        srt_notes_builder = SRTNotesBuilder(self.flaw, self.old_flaw)
        self._query["cf_srtnotes"] = srt_notes_builder.content

    def generate_comment(self):
        pending_comments = FlawComment.objects.pending().filter(flaw=self.flaw)

        if pending_comments.exists():
            self._query["comment"] = {
                "body": pending_comments.first().text,
                "is_private": False,
            }
