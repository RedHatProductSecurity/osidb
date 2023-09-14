"""
common tracker functionality shared between BTSs
"""
from functools import cached_property
from urllib.parse import urljoin

from apps.trackers.constants import (
    KERNEL_PACKAGES,
    MAX_SUMMARY_LENGTH,
    MULTIPLE_DESCRIPTIONS_SUBSTITUTION,
    VIRTUALIZATION_PACKAGES,
)
from apps.trackers.exceptions import TrackerCreationError
from collectors.bzimport.constants import BZ_URL
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

            cves, description = self._summary_shorten(cves, description)

        return summary

    def _summary_prefixes(self) -> str:
        """
        generate string of sorted tracker summary prefixes
        """
        prefixes = []

        if self.tracker.is_embargoed:
            prefixes.append("EMBARGOED")

        if any(
            flaw
            for flaw in self.flaws
            if flaw.major_incident_state == Flaw.FlawMajorIncident.APPROVED
        ):
            prefixes.append("[Major Incident]")

        # we can theoretically have normal and CISA one at once
        # and then we prioritize the normal one above CISA
        elif any(
            flaw
            for flaw in self.flaws
            if flaw.major_incident_state == Flaw.FlawMajorIncident.CISA_APPROVED
        ):
            prefixes.append("[CISA Major Incident]")

        # TODO TRIAGE prefix is based on the flaw workflow state
        # be aware that it is still undefined for trackers with multiple flaws

        if not prefixes:
            return ""

        # join sorted prefixes with space delimiter and
        # add a trailing space to separate from the rest
        return " ".join(sorted(prefixes)) + " "

    def _summary_shorten(self, cves, description):
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
                raise TrackerCreationError(
                    f"Summary generated for the tracker is longer than {MAX_SUMMARY_LENGTH}"
                )

            # simply shorten the desciption by one
            description = description[0:-5] + " ..."

        return cves, description

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
        # tracked in https://issues.redhat.com/browse/OSIDB-1191

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

            # 3b) triage text
            if self.tracker.is_triage:
                description_parts.extend(self._description_triage())

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
            description_parts.extend(self._description_kernel())

        # 5) join the parts by empty lines
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

        header = ""
        if self.tracker.is_triage:
            header += "Potential "

        header += (
            f"{self.ps_module.name} tracking bug for {self.ps_component}: "
            'see the bugs linked in the "Blocks" field of this bug '
            "for full details of the security issue(s)."
        )
        description_parts.append(header)

        description_parts.append(
            "This bug is never intended to be made public, "
            "please put any public notes in the blocked bugs."
        )
        return description_parts

    # TODO this should be eventually replaced by the OSIM/OSIDB link
    def _description_bugzilla_link(self, bz_id):
        """
        generate link to Bugzilla bug with the given ID
        """
        return urljoin(BZ_URL, f"show_bug.cgi?id={bz_id}")

    def _description_community(self):
        """
        generate community tracker description text
        """
        description_parts = []
        description_parts.append(
            "More information about this security flaw is available in the following bug:"
            if len(self.flaws) == 1
            else "More information about these security flaws is available in the following bugs:"
        )
        description_parts.append(
            "\n".join(
                [self._description_bugzilla_link(flaw.bz_id) for flaw in self.flaws]
            )
        )
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
            reference_url = self._description_bugzilla_link(flaw.bz_id)

            description_parts.append(f"{flaw.title}\n{reference_url}")
            description_parts.append(flaw.description)

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

        header += (
            "Security Issue Notification"
            if self.tracker.is_triage
            else "Security Tracking Issue"
        )
        description_parts.append(header)

        if self.ps_module.private_trackers_allowed:
            description_parts.append("Do not make this issue public.")

        return description_parts

    def _description_kernel(self):
        """
        generate kernel tracker description text
        """
        return [
            "Reproducers, if any, will remain confidential and never be made public, "
            "unless done so by the security team."
        ]

    def _description_triage(self):
        """
        generate triage tracker description text
        """
        description_parts = []
        description_parts.append(
            "This is a preliminary notification of a potential vulnerability under "
            'the accelerated "Triage Tracker" program introduced between Product Security '
            "and Engineering to allow deeper collaboration."
        )
        description_parts.append(
            "The in-depth analysis is ongoing, and details are expected to change until "
            "such time as it concludes."
        )
        description_parts.append(
            "Be aware that someone other than the analyst performing the Secondary Assessment "
            "will usually create the triage tracker. The best option is to comment in the "
            "tracker and wait for a reply. Based on your regular interactions, "
            "if you know the Incident Response Analyst for your offering, you can reach out "
            "to them directly or add a private comment in the triage tracker or in "
            "the flaw bug for their attention."
        )
        description_parts.append(
            "Please refer to the FAQ page for more information - "
            "https://source.redhat.com/departments/products_and_global_engineering/product_security/content/product_security_wiki/incident_response_coordination_faq"
        )
        return description_parts
