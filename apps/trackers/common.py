"""
common tracker functionality shared between BTSs
"""
from functools import cached_property

from apps.trackers.constants import (
    MAX_SUMMARY_LENGTH,
    MULTIPLE_DESCRIPTIONS_SUBSTITUTION,
)
from apps.trackers.exceptions import TrackerCreationError
from osidb.helpers import cve_id_comparator
from osidb.models import Flaw, PsModule, PsUpdateStream


class TrackerQueryBuilder:
    """
    common base for the shared query building functionality
    """

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
