"""
common tracker functionality shared between BTSs
"""

from functools import cached_property

from apps.bbsync.constants import MAX_SUMMARY_LENGTH, MULTIPLE_DESCRIPTIONS_SUBSTITUTION
from apps.bbsync.query import summary_shorten
from apps.trackers.constants import (
    KERNEL_PACKAGES,
    VIRTUALIZATION_PACKAGES,
    VULN_MGMT_INFO_URL,
)
from apps.trackers.jira.constants import TRACKER_FEEDBACK_FORM_URL
from osidb.helpers import cve_id_comparator
from osidb.models import Flaw, PsModule, PsUpdateStream, Tracker


class TrackerQueryBuilder:
    """
    common base for the shared query building functionality
    """

    @property
    def query(self):
        """
        query getter shorcut
        """
        if self._query is None:
            self.generate()

        return self._query

    def generate(self):
        """
        generate query
        """
        raise NotImplementedError

    @property
    def tracker(self):
        """
        concrete name shortcut
        """
        return self.instance

    @property
    def is_creating(self):
        """
        True on tracker creation
        """
        return not self.tracker.external_system_id

    @cached_property
    def flaws(self):
        """
        cached flaws getter
        """
        return [affect.flaw for affect in self.tracker.affects.all()]

    @cached_property
    def ps_module(self):
        """
        cached PS module getter
        """
        # even when multiple affects they must all have the same PS module
        return PsModule.objects.get(name=self.tracker.affects.first().ps_module)

    @cached_property
    def ps_component(self):
        """
        cached PS component getter
        """
        # even when multiple affects they must all have the same PS component
        return self.tracker.affects.first().ps_component

    @cached_property
    def ps_update_stream(self):
        """
        cached PS update stream getter
        """
        return PsUpdateStream.objects.get(name=self.tracker.ps_update_stream)

    @cached_property
    def summary(self):
        """
        tracker summary getter
        """
        prefixes = self._summary_prefixes()
        cves = sorted(
            [flaw.cve_id for flaw in self.flaws if flaw.cve_id], key=cve_id_comparator
        )
        # we can assume that the tracker has a positive number of flaws
        # associated which are all different because it is validated
        description = (
            self.flaws[0].title
            if len(self.flaws) == 1
            else MULTIPLE_DESCRIPTIONS_SUBSTITUTION
        )

        # try to compose the summary
        # until it is short enough
        while True:
            cve_string = " ".join(cves) + " " if cves else ""
            summary = f"{prefixes}{cve_string}{self.ps_component}: {description} [{self.ps_update_stream.name}]"

            if len(summary) <= MAX_SUMMARY_LENGTH:
                break

            cves, description = summary_shorten(cves, description)

        return summary

    def _summary_prefixes(self) -> str:
        """
        generate string of sorted tracker summary prefixes
        """
        prefixes = []

        if self.tracker.is_embargoed:
            prefixes.append("EMBARGOED")

        prefix_map = {
            Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED: "[Major Incident]",
            Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED: "[Exploits (KEV)]",
            Flaw.FlawMajorIncident.MINOR_INCIDENT_APPROVED: "[Minor Incident]",
        }

        # no incident priority has been given
        # thus let us assume there is none
        for flaw in sorted(self.flaws, key=lambda flaw: flaw.major_incident_state):
            if flaw.major_incident_state in prefix_map:
                prefixes.append(prefix_map[flaw.major_incident_state])
                break

        if not prefixes:
            return ""

        # join sorted prefixes with space delimiter and
        # add a trailing space to separate from the rest
        return " ".join(sorted(prefixes)) + " "

    @cached_property
    def description(self):
        """
        tracker description getter
        """
        # the old-tooling tracker description creation is basically long if-else
        # adding more and more parts into an exising description base so we mimic
        # it by composing an array of parts to be joined together at the very end
        description_parts = []

        # TODO
        # 1) use the template instead if any
        # tracked in https://uat-1-1-redhat.atlassian.net/browse/OSIDB-1191

        # 2) special community comment header
        if self.ps_module.ps_product.is_community:
            description_parts.extend(self._description_community())

        # 3) compose the regular tracker description
        #    considering all the relevant conditions
        #
        #    Bugzilla and Jira parts are obviously mutulally
        #    exclusive but other parts are not and the order
        #    even though it may seem random is taken from
        #    SFM2 exactly the way it was defined there
        else:
            # 3a) Jira header
            if self.tracker.type == Tracker.TrackerType.JIRA:
                description_parts.extend(self._description_jira_header())

            # 3b) was "triage text"
            #     Not renumbering to keep potential
            #     discussions about the code non-confusing.

            # 3c) Bugzilla header
            if self.tracker.type == Tracker.TrackerType.BUGZILLA:
                description_parts.extend(self._description_bugzilla_header())

            # 3d) SLA text
            if self.ps_update_stream.rhsa_sla_applicable:
                pass  # TODO

            # 3e) embargo text
            if self.tracker.is_embargoed:
                description_parts.extend(self._description_embargoed())

            # 3f) Jira footer
            if self.tracker.type == Tracker.TrackerType.JIRA:
                description_parts.extend(self._description_jira_footer())

            # 3g) Bugzilla footer
            if self.tracker.type == Tracker.TrackerType.BUGZILLA:
                description_parts.extend(self._description_bugzilla_footer())

        # 4) another extra bit for kernel
        if self.ps_component in KERNEL_PACKAGES:
            description_parts.extend(TrackerQueryBuilder._description_kernel())

        # 5) Link to vulnerability management information (internal trackers only)
        if not self.ps_module.ps_product.is_community:
            description_parts.extend(self._description_vuln_mgmt_info())

        # 6) Tracker feedback form for Jira
        if self.tracker.type == Tracker.TrackerType.JIRA:
            description_parts.extend(self._description_feedback_form())

        # 7) join the parts by empty lines
        return "\n\n".join(description_parts)

    def _description_bugzilla_footer(self):
        """
        generate Bugzilla tracker description footer
        """
        description_parts = []

        if self.tracker.is_embargoed:
            if self.ps_component in KERNEL_PACKAGES:
                description_parts.append(
                    "Information with regards to this bug is considered Red Hat Confidential "
                    "until the embargo has lifted. Please post the patch only to the "
                    "'rhkernel-team-list' mailing list for review and acks."
                )

            if self.ps_component in VIRTUALIZATION_PACKAGES:
                description_parts.append(
                    "Information with regards to this bug is considered Red Hat Confidential "
                    "until the embargo has lifted. Please post the patch only to the "
                    "'rhkernel-team-list' and/or 'virt-devel' mailing lists for review and acks."
                )

        if self.ps_module.name.startswith("rhel-"):
            description_parts.append(
                "For the Enterprise Linux security issues handling process overview see:\n"
                "https://source.redhat.com/groups/public/product-security/content/product_security_wiki/eus_z_stream_and_security_bugs"
            )

        return description_parts

    def _description_bugzilla_header(self):
        """
        generate Bugzilla tracker description header
        """
        description_parts = []

        header = f"{self.ps_module.name} tracking bug for {self.ps_component}."
        description_parts.append(header)

        description_parts.append(
            "This bug is never intended to be made public, "
            "please put any public notes in the blocked bugs."
        )
        return description_parts

    def _description_community(self):
        """
        generate community tracker description text
        """
        description_parts = []
        description_parts.append(
            "Disclaimer: Community trackers are created by Red Hat Product Security team on a "
            "best effort basis. Package maintainers are required to ascertain if the flaw indeed "
            "affects their package, before starting the update process."
        )
        return description_parts

    def _description_embargoed(self):
        """
        generate embargoed tracker description text
        """
        description_parts = []
        description_parts.append(
            "NOTE THIS ISSUE IS CURRENTLY EMBARGOED, "
            "DO NOT MAKE PUBLIC COMMITS OR COMMENTS ABOUT THIS ISSUE."
        )

        if self.tracker.type == Tracker.TrackerType.JIRA:
            description_parts.append(
                "WARNING: NOTICE THAT CHANGING THE SECURITY LEVEL FROM "
                '"SECURITY ISSUE" TO "RED HAT INTERNAL" MAY BREAK THE EMBARGO.'
            )

        if self.tracker.type == Tracker.TrackerType.BUGZILLA:
            description_parts.append(
                'WARNING: NOTICE THAT REMOVING THE "SECURITY" '
                "GROUP FROM THIS TRACKER MAY BREAK THE EMBARGO."
            )

        return description_parts

    def _description_jira_footer(self):
        """
        generate Jira tracker description footer
        """
        description_parts = []
        description_parts.append(
            "Flaw:\n-----" if len(self.flaws) == 1 else "Flaws:\n------"
        )

        for flaw in self.flaws:
            description_parts.append(f"{flaw.title}")
            description_parts.append(flaw.comment_zero)

        description_parts.append("~~~")
        return description_parts

    def _description_jira_header(self):
        """
        generate Jira tracker description header
        """
        description_parts = []

        header = ""
        # private trackers are not allow so we are public
        if not self.ps_module.private_trackers_allowed:
            header += "Public "

        header += "Security Tracking Issue"
        description_parts.append(header)

        if self.ps_module.private_trackers_allowed:
            description_parts.append("Do not make this issue public.")

        return description_parts

    def _description_kernel():
        """
        generate kernel tracker description text
        """
        return [
            "Reproducers, if any, will remain confidential and never be made public, "
            "unless done so by the security team."
        ]

    def _description_feedback_form(self):
        """
        generate tracker feedback form text
        """
        if TRACKER_FEEDBACK_FORM_URL is None:
            return []
        return [f"Tracker accuracy feedback form: {TRACKER_FEEDBACK_FORM_URL}"]

    def _description_vuln_mgmt_info(self):
        """
        generate vulnerability management link and text
        """
        if VULN_MGMT_INFO_URL is None:
            return []
        return [
            "The following link provides references to all essential vulnerability management information. "
            "If something is wrong or missing, please contact a member of PSIRT.\n"
            f"{VULN_MGMT_INFO_URL}"
        ]
