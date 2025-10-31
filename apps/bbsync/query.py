import json
from datetime import timedelta
from itertools import chain

from django.utils import timezone

from apps.bbsync.constants import MAX_SUMMARY_LENGTH, MULTIPLE_DESCRIPTIONS_SUBSTITUTION
from apps.bbsync.exceptions import UnsavableModelError
from collectors.bzimport.constants import ANALYSIS_TASK_PRODUCT
from osidb.cc import BugzillaFlawCCBuilder
from osidb.helpers import cve_id_comparator, filter_cves
from osidb.models import Flaw, FlawComment, Impact, PsModule

from .constants import DATE_FMT


def summary_shorten(cves, description):
    """
    shorten the aligable parts of the tracker summary
    """
    # first shorten CVE list
    if len(cves) > 1:
        # remove the last CVE
        cves = cves[0:-1]
        # add the dots to the new last
        cves[-1] = cves[-1] + " ..."

    # finally shorten the description
    else:
        # when we cannot preserve at least a minimal meaningful description
        # something is fairly wrong and we cannot create such tracker
        if len(description) <= len(MULTIPLE_DESCRIPTIONS_SUBSTITUTION):
            raise UnsavableModelError(
                f"Summary generated for the tracker is longer than {MAX_SUMMARY_LENGTH}"
            )

        # simply shorten the desciption by one
        description = description[0:-5] + " ..."

    return cves, description


class BugzillaQueryBuilder:
    """
    Bugzilla bug query builder
    containing shared funtionality

    https://bugzilla.redhat.com/docs/en/html/api/index.html
    """

    def __init__(self, instance):
        """
        init stuff
        """
        self.instance = instance
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
    def is_creating(self):
        """
        boolean property True on creation and False on update
        """
        return self.instance.bz_id is None

    _meta_attr = None

    @property
    def meta_attr(self):
        """
        concrete name shortcut
        """
        if not self._meta_attr:
            self._meta_attr = self.instance.meta_attr
        return self._meta_attr

    @property
    def groups(self):
        return json.loads(self.meta_attr.get("groups", "[]"))

    @groups.setter
    def groups(self, groups):
        self.meta_attr["groups"] = json.dumps(sorted(groups))

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
    def cc(self):
        return json.loads(self.meta_attr.get("cc", "[]"))

    @cc.setter
    def cc(self, cc):
        self.meta_attr["cc"] = json.dumps(cc)

    @property
    def cve_id(self):
        cves = filter_cves(json.loads(self.meta_attr.get("alias", "[]")))
        # BBSync does not accept multi-CVE flaws
        # therefore we may safely pick the first
        return cves[0] if cves else None

    @cve_id.setter
    def cve_id(self, cve_id):
        aliases = filter_cves(
            json.loads(self.meta_attr.get("alias", "[]")), inverse=True
        )
        # preserve non-CVE aliases
        if cve_id is not None:
            aliases.append(cve_id)
        self.meta_attr["alias"] = json.dumps(aliases)

    def add_aliases(self, aliases):
        old_aliases = json.loads(self.meta_attr.get("alias", "[]"))
        new_aliases = sorted(list(set(aliases) | set(old_aliases)))
        self.meta_attr["alias"] = json.dumps(new_aliases)

    @property
    def embargoed(self):
        return "security" in self.groups

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
        self.generate_comment()
        self.generate_fixed_in()

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

        component = "vulnerability"

        if self.flaw.workflow_state in [
            Flaw.WorkflowState.NEW,
            Flaw.WorkflowState.REJECTED,
        ] and self.flaw.meta_attr.get("bz_component") in [None, "vulnerability-draft"]:
            component = "vulnerability-draft"

        self._query["component"] = component

    def generate_unconditional(self):
        """
        generate query attributes not requiring conditional processing
        """
        self._query["cf_release_notes"] = self.flaw.cve_description
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

        # 1) add the CVE ID from the flaw being updated or created
        cve_ids = [self.flaw.cve_id]
        # 2) get all CVE IDs of flaws with the same Bugzilla ID
        #    (this is to cover the cases of multi-CVE flaws)
        #    except the one which is just being updated or created
        #    as the DB instance may differ from this change
        if self.flaw.bz_id:
            cve_ids = cve_ids + [
                f.cve_id
                for f in Flaw.objects.filter(meta_attr__bz_id=self.flaw.bz_id).exclude(
                    uuid=self.flaw.uuid
                )
            ]
        # 3) filter out the empty CVE IDs
        #    there can be one in case we are removing the CVE ID
        cve_ids = [cve_id for cve_id in cve_ids if cve_id]
        # 4) filter out eventual duplicates | sort by CVE ID
        cve_ids = sorted(list(set(cve_ids)), key=cve_id_comparator)

        components = (
            ": ".join([component for component in self.flaw.components]) + ": "
            if self.flaw.components
            else ""
        )

        # try to compose the summary
        # until it is short enough
        description = self.flaw.title
        while True:
            cve_string = " ".join(cve_ids) + " " if cve_ids else ""
            summary = f"{embargoed}{cve_string}{components}{description}"

            if len(summary) <= MAX_SUMMARY_LENGTH:
                break

            cve_ids, description = summary_shorten(cve_ids, description)

        self._query["summary"] = summary

    def generate_description(self):
        """
        generate query for flaw description on create
        """
        if self.is_creating:
            self._query["description"] = self.flaw.comment_zero
            self._query["comment_is_private"] = False

    def generate_alias(self):
        """
        generate add or remove CVE alias query
        conditionally based on the changes and create|update

        if a collector created a flaw, check the external ID, as CVE might not be present
        """
        if self.is_creating:
            if self.flaw.cve_id is not None:
                # create query requires pure list
                self._query["alias"] = [self.flaw.cve_id]

            elif snippets := self.flaw.snippets.all():
                aliases = [s.external_id for s in snippets]
                self._query["alias"] = aliases
                # update alias in meta_attr
                self.add_aliases(aliases)

        elif self.flaw.cve_id != self.cve_id:
            self._query["alias"] = {}

            if self.flaw.cve_id is not None:
                self._query["alias"]["add"] = [self.flaw.cve_id]

            if self.cve_id is not None:
                self._query["alias"]["remove"] = [self.cve_id]

        # update alias in meta_attr
        self.cve_id = self.flaw.cve_id

    def generate_keywords(self):
        """
        generate keywords query based on creation|update
        """
        self._query["keywords"] = (
            ["Security"] if self.is_creating else {"add": ["Security"]}
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
            Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED: ("?", "?"),
            Flaw.FlawMajorIncident.MAJOR_INCIDENT_REJECTED: ("-", "-"),
            Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED: ("+", "-"),
            Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED: ("-", "+"),
            # flags NOVALUE is ignored
        }

        if self.flaw.major_incident_state in flags_to_write:
            hightouch, hightouch_lite = flags_to_write[self.flaw.major_incident_state]

            self._query["flags"].append({"name": "hightouch", "status": hightouch})
            self._query["flags"].append(
                {"name": "hightouch-lite", "status": hightouch_lite}
            )

    def generate_requires_doc_text_flag(self):
        """
        Generate requires_doc_text flag from requires_cve_description
        """
        flags_to_write = {
            Flaw.FlawRequiresCVEDescription.REQUESTED: "?",
            Flaw.FlawRequiresCVEDescription.APPROVED: "+",
            Flaw.FlawRequiresCVEDescription.REJECTED: "-",
            # flag NOVALUE is ignored
        }

        if bz_value := flags_to_write.get(self.flaw.requires_cve_description):
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
            # we care for affects with a tracker only
            module_names = [
                affect.ps_module
                for affect in self.flaw.affects.filter(tracker__isnull=False)
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
        if self.is_creating:
            self._query["groups"] = groups

        # otherwise we provide the differences
        else:
            add_groups, remove_groups = self._lists2diffs(groups, self.groups)
            self._query["groups"] = {
                "add": add_groups,
                "remove": remove_groups,
            }

        # update groups in meta_attr
        self.groups = groups

    def generate_deadline(self):
        """
        generate query for Bugzilla deadline
        """
        if self.flaw.is_embargoed:
            if self.flaw.unembargo_dt:
                self._query["deadline"] = self.flaw.unembargo_dt.strftime(DATE_FMT)

        # unembargo
        elif not self.is_creating and self.embargoed:
            self._query["deadline"] = ""

    def generate_cc(self):
        """
        generate query for CC list
        """
        cc_builder = BugzillaFlawCCBuilder(self.flaw, self.cc)
        # let us ignore CCs to be removed
        add_cc, _ = cc_builder.content

        if self.is_creating:
            self._query["cc"] = add_cc

        else:
            self._query["cc"] = {"add": add_cc}

        # update CC in meta_attr by just accumulating
        self.cc = list(set(self.cc) | set(add_cc))

    def generate_comment(self):
        """
        Performs best-effort sending of new comments to bugzilla.
        Assumes that when a comment is created via API, the processing is quick enough to
        reach this point within 20 seconds.
        If a comment doesn't get sent but is committed to the database, it's not resent later.
        """
        # If for some reason a comment doesn't get sent to BZ (e.g. disabling bbsync temporarily),
        # avoid sending it once the comment is old (that would create confusion in BZ).
        past_20s = timezone.now() - timedelta(seconds=20)

        pending_comment = (
            FlawComment.objects.filter(flaw=self.flaw)
            .filter(external_system_id="")
            .filter(synced_to_bz=False)
            .filter(created_dt__gte=past_20s)
            .last()
        )

        if pending_comment:
            self._query["comment"] = {
                "body": pending_comment.text,
                "is_private": pending_comment.is_private,
            }
            pending_comment.synced_to_bz = True
            pending_comment.save(auto_timestamps=False)

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
