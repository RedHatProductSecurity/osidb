"""
Jira tracker funtionality module
"""
from typing import Any, Dict

from apps.trackers.exceptions import NoPriorityAvailableError
from apps.trackers.models import JiraProjectFields
from osidb.models import FlawImpact

from .bts_tracker import BTSTracker


class JiraPriority:
    """
    Allowed Jira priorities compliant with OJA-PRIS-001
    """

    BLOCKER = "Blocker"
    CRITICAL = "Critical"
    MAJOR = "Major"
    NORMAL = "Normal"
    MINOR = "Minor"
    UNDEFINED = "Undefined"


IMPACT_TO_JIRA_PRIORITY = {
    FlawImpact.CRITICAL: [JiraPriority.CRITICAL],
    FlawImpact.IMPORTANT: [JiraPriority.MAJOR],
    FlawImpact.MODERATE: [
        JiraPriority.NORMAL,
        JiraPriority.MINOR,
    ],  # some projects still miss Normal priority
    FlawImpact.LOW: [JiraPriority.MINOR],
    # mapping below is just safeguard
    # but we should never file such trackers
    FlawImpact.NOVALUE: [JiraPriority.UNDEFINED],
}


class JiraTracker(BTSTracker):
    """
    In-memory Tracker object used to generate text that is
    compliant with IR team processes for trackers using Jira
    """

    def _generate_labels(self) -> list[str]:
        """
        Generates labels used by Jira to filter trackers
        """
        labels = []
        if self._affect.ps_component:
            labels.append(f"pscomponent:{self._affect.ps_component}")
        labels.append(self._flaw.cve_id)
        labels.append("Security")
        labels.append("SecurityTracking")

        return labels

    def _impact_to_priority(self) -> JiraPriority:
        """
        Convert OSIDB impact ot Jira Priority
        """
        allowed_values = JiraProjectFields.objects.get(
            project_key=self._ps_module.bts_key, field_id="priority"
        ).allowed_values
        allowed_values = [value["name"] for value in allowed_values]
        for priority in IMPACT_TO_JIRA_PRIORITY[self._flaw.impact]:
            if priority in allowed_values:
                return priority

        raise NoPriorityAvailableError(
            f"Jira project {self._ps_module.bts_key} does not have a corresponding priority for impact "
            f"{self._flaw.impact}; allowed Jira priority values are: {', '.join(allowed_values)}"
        )

    def _generate_description(self) -> str:
        """
        Generates a text description for the vulnerability being tracked
        """
        if self._flaw.is_embargoed:
            description = "Security Tracking Issue\n\nDo not make this issue public.\n"
        else:
            description = "Public Security Tracking Issue\n"
        description += (
            f"https://osidb.prodsec.redhat.com/osidb/api/v1/flaws/{self._flaw.uuid}.\n"
        )

        return description

    def generate_bts_object(self) -> Dict[str, Any]:
        """
        Generates an object that can be used to create a new Jira tracker
        """
        bts_tracker = {
            "fields": {
                "project": {"key": self._ps_module.bts_key},
                "issuetype": {"name": "Bug"},
                "priority": {"name": self._impact_to_priority()},
                "summary": self._generate_summary(),
                "description": self._generate_description(),
                "labels": self._generate_labels(),
            }
        }
        if self._flaw.is_embargoed:
            bts_tracker["fields"]["security"] = {"name": "Embargoed Security Issue"}
        existing_tracker = self._affect.trackers.filter(
            ps_update_stream=self._stream.name
        ).first()

        if existing_tracker:
            bts_tracker["key"] = existing_tracker.external_system_id
            bts_tracker["fields"]["status"] = {"name": existing_tracker.status}
            if existing_tracker.resolution:
                bts_tracker["fields"]["resolution"] = {
                    "name": existing_tracker.resolution
                }

        return bts_tracker
