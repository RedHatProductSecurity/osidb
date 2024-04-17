import json
from itertools import chain

from collectors.bzimport.constants import ANALYSIS_TASK_PRODUCT
from osidb.helpers import cve_id_comparator
from osidb.models import Flaw, FlawComment, Impact, PsModule

from .cc import CCBuilder
from .constants import DATE_FMT
from .srtnotes import SRTNotesBuilder


class BugzillaQueryBuilder:
    """
    Bugzilla bug query builder
    containing shared funtionality

    https://bugzilla.redhat.com/docs/en/html/api/index.html
    """

    def __init__(self, instance, old_instance=None):
        """
        init stuff
        parametr old_instance is optional as there is no old instance on creation
        and if not set we consider the query to be a create query
        """
        self.instance = instance
        self.old_instance = old_instance
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
        """
        boolean property True on creation and False on update
        """
        return self.old_instance is None

    def generate(self):
        """
        generate query
        """
        raise NotImplementedError

    IMPACT_TO_SEVERITY_PRIORITY = {
        Impact.CRITICAL: "urgent",
        Impact.IMPORTANT: "high",
        Impact.MODERATE: "medium",
        Impact.LOW: "low",
        Impact.NOVALUE: "unspecified",
    }

    def _lists2diffs(self, new_list, old_list):
        """
        take the new and the old list and return
        the differences to be added and removed
        """
        to_add = list(set(new_list) - set(old_list))
        to_remove = list(set(old_list) - set(new_list))
        return to_add, to_remove


class FlawBugzillaQueryBuilder(BugzillaQueryBuilder):
    """
    Bugzilla flaw bug query builder
    to generate general flaw save query
    """

    @property
    def flaw(self):
        """
        concrete name shortcut
        """
        return self.instance

    @property
    def old_flaw(self):
        """
        concrete name shortcut
        """
        return self.old_instance

    def generate(self):
        """
        generate query
        """
        self.generate_base()
        self.generate_component()
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
        self.generate_fixed_in()
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
            "op_sys": "Linux",
            "platform": "All",
            "version": "unspecified",
        }

    def generate_component(self):
        """
        generate component to differentiate between flaw and flaw draft
        """
        self._query["component"] = (
            "vulnerability-draft" if self.flaw.is_draft else "vulnerability"
        )

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
        TODO: needinfo and other flags
        """
        self._query["flags"] = []
        self.generate_hightouch_flags()
        self.generate_requires_doc_text_flag()
        self.generate_nist_cvss_validation_flag()

    def generate_hightouch_flags(self):
        """
        Generate hightouch and hightouch-lite flags from major_incident_state.
        """
        flags_to_write = {
            Flaw.FlawMajorIncident.REQUESTED: ("?", "?"),
            Flaw.FlawMajorIncident.REJECTED: ("-", "-"),
            Flaw.FlawMajorIncident.APPROVED: ("+", "-"),
            Flaw.FlawMajorIncident.CISA_APPROVED: ("-", "+"),
            # flags NOVALUE and INVALID are ignored
        }

        if self.flaw.major_incident_state in flags_to_write:
            hightouch, hightouch_lite = flags_to_write[self.flaw.major_incident_state]

            self._query["flags"].append({"name": "hightouch", "status": hightouch})
            self._query["flags"].append(
                {"name": "hightouch-lite", "status": hightouch_lite}
            )

    def generate_requires_doc_text_flag(self):
        """
        Generate requires_doc_text flag from requires_summary.
        """
        flags_to_write = {
            Flaw.FlawRequiresSummary.REQUESTED: "?",
            Flaw.FlawRequiresSummary.APPROVED: "+",
            Flaw.FlawRequiresSummary.REJECTED: "-",
            # flag NOVALUE is ignored
        }

        if bz_value := flags_to_write.get(self.flaw.requires_summary):
            self._query["flags"].append(
                {"name": "requires_doc_text", "status": bz_value}
            )

    def generate_nist_cvss_validation_flag(self):
        """
        Generate nist_cvss_validation bugzilla flag from Flaw field nist_cvss_validation.
        """

        flag_to_write = {
            Flaw.FlawNistCvssValidation.REQUESTED: "?",
            Flaw.FlawNistCvssValidation.APPROVED: "+",
            Flaw.FlawNistCvssValidation.REJECTED: "-",
            # flag NOVALUE is ignored
        }

        if flag_value := flag_to_write.get(self.flaw.nist_cvss_validation):
            self._query["flags"].append(
                {"name": "nist_cvss_validation", "status": flag_value}
            )

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

        elif self.flaw.is_internal:
            groups = ["redhat"]

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

    def generate_fixed_in(self):
        """
        Generates bugzilla query value for the bugzilla field fixed_in based
        on the hierarchy of Flaw-associated models Package and PackageVer.

        Except for flaws that have been stored in the database for a long time
        and haven't been refreshed by bzimport since introducing this function
        (and the associated save_packageversions in convertors.py). For such,
        the bugzilla query for the flag is silently not generated.
        """

        if "fixed_in" not in self.flaw.meta_attr:
            # TODO: Consider manually bzimporting leftover Flaws without
            #       meta_attr["fixed_in"] before prod goes writable. It might be
            #       a manageable number by then.
            # TODO: [File an issue to track this, add the OSIDB-<number> ID here.]
            #
            # Do not send fixed_in to bugzilla. If this bbsync runs because of an API request
            # to edit fixed_in, the change will be silently discarded.
            #
            # * If this branch executes, this flaw has not been updated in OSIDB database since
            #   adding support for fixed_in. That's a long time.
            # * OSIDB is planned to run for months with meta_attr["fixed_in"] support before the
            #   first usage of the API for modification of fixed_in
            #   (/flaw/<flaw_id>/package_versions). Therefore on most Flaws where users might need
            #   modifying fixed_in, meta_attr["fixed_in"] will have already been bzimported by the
            #   time they start doing so.
            # * We can't just blanket raise an exception when meta_attr["fixed_in"] is missing
            #   because that would block all bbsync operations for all not-yet-bzimported Flaws.
            # * Detecting API-performed changes without flaw.meta_attr["fixed_in"] would be
            #   nontrivial, so intelligently deciding when to raise such an exception would also be
            #   nontrivial.
            # * The most proper way would be to bzimport the Flaw here and populate meta_attr.
            #   However, that is potentially complicated and breaks decomposition for a probably
            #   miniscule benefit.
            # * Any Flaw bbsync triggers a follow-up bzimport that will load meta_attr["fixed_in"].
            #   We can expect that if an old Flaw gets updated, fixed_in will not be the first
            #   edit operation.
            #
            return

        # Tokenize the existing state of fixed_in to find out whether " " or "-" was used for
        # delimiting the package-version pairs. The algorithm is similar to
        # FlawConvertor.package_versions.
        original_fixed_in = []
        for token in self.flaw.meta_attr["fixed_in"].split(","):
            token = token.strip()
            token_items = token.split(" ", 1)
            if len(token_items) == 1:
                # fixed_in version can be split with ' ', or '-'
                token_items = token.rsplit("-", 1)
                if len(token_items) == 1:
                    # FlawConvertor ignores such a token, do the same here.
                    continue
                pkg = token_items[0]
                separator = "-"
                ver = token_items[1]
            else:
                pkg = token_items[0]
                separator = " "
                ver = token_items[1]
            original_fixed_in.append((pkg, separator, ver))

        # New package-version pairs based on current models.
        proposed_fixed_in = set()
        for pkg_obj in self.flaw.package_versions.all():
            for ver_obj in pkg_obj.versions.all():
                proposed_fixed_in.add((pkg_obj.package, ver_obj.version))

        # Consolidate new and old.
        result = []
        # Preserve order of existing versions in fixed_in, but remove those that were deleted.
        for pkg, separator, ver in original_fixed_in:
            if (pkg, ver) in proposed_fixed_in:
                result.append(f"{pkg}{separator}{ver}")
                proposed_fixed_in.remove((pkg, ver))
        # And also add newly added versions to fixed_in.
        result.extend(sorted([f"{pkg} {ver}" for (pkg, ver) in proposed_fixed_in]))

        self._query["cf_fixed_in"] = ", ".join(result)
