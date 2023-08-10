"""
Jira tracker query generation module
"""
import logging
from functools import cached_property

from apps.trackers.common import TrackerQueryBuilder
from apps.trackers.exceptions import NoPriorityAvailableError
from apps.trackers.models import JiraProjectFields
from osidb.models import Impact

logger = logging.getLogger(__name__)


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
    Impact.CRITICAL: [JiraPriority.CRITICAL],
    Impact.IMPORTANT: [JiraPriority.MAJOR],
    Impact.MODERATE: [
        JiraPriority.NORMAL,
        JiraPriority.MINOR,
    ],  # some projects still miss Normal priority
    Impact.LOW: [JiraPriority.MINOR],
    # mapping below is just safeguard
    # but we should never file such trackers
    Impact.NOVALUE: [JiraPriority.UNDEFINED],
}


class TrackerJiraQueryBuilder(TrackerQueryBuilder):
    """
    Jira tracker bug query builder
    to generate general tracker save query
    """

    def __init__(self, instance):
        """
        init stuff
        """
        self.instance = instance
        self._query = {}

    @cached_property
    def impact(self):
        """
        cached tracker maximum impact
        """
        return self.tracker.aggregated_impact

    @cached_property
    def reported_dt(self):
        """
        cached earliest reported date
        """
        self.tracker.affects.order_by("flaw__reported_dt")[0].flaw.reported_dt

    def generate(self):
        """
        generate query
        """
        self.generate_base()
        self.generate_priority()
        self.generate_deadline()
        self.generate_description()
        self.generate_labels()
        self.generate_summary()

    def generate_base(self):
        self._query = {
            "fields": {
                "issuetype": {"name": "Bug"},
                "project": {"key": self.ps_module.bts_key},
            }
        }
        if self.tracker.external_system_id:
            self._query["key"] = self.tracker.external_system_id

    def generate_priority(self):
        """
        Convert OSIDB impact to Jira Priority
        """
        allowed_values = JiraProjectFields.objects.get(
            project_key=self.ps_module.bts_key, field_id="priority"
        ).allowed_values
        allowed_values = [value["name"] for value in allowed_values]
        for priority in IMPACT_TO_JIRA_PRIORITY[self.impact]:
            if priority in allowed_values:
                self._query["fields"]["priority"] = {"name": priority}
                return

        raise NoPriorityAvailableError(
            f"Jira project {self.ps_module.bts_key} does not have a corresponding priority for impact "
            f"{self.impact}; allowed Jira priority values are: {', '.join(allowed_values)}"
        )

    def generate_deadline(self):
        """
        generate query for Bugzilla deadline
        """
        # TODO SLA module
        pass

    def generate_description(self):
        """
        Generates a text description for the vulnerability being tracked
        """
        if self.tracker.embargoed:
            description = "Security Tracking Issue\n\nDo not make this issue public.\n"
        else:
            description = "Public Security Tracking Issue\n"

        description += (
            f"Impact: {self.impact}.\n"
            f"Reported Date: {self.reported_dt}.\n\n"
            "Flaw:\n-----"
        )
        for affect in self.tracker.affects.all():
            description += f"https://osidb.prodsec.redhat.com/osidb/api/v1/flaws/{affect.flaw.uuid}\n"

    def generate_labels(self):
        """
        generate query for Jira labels
        """
        cve_ids = self.tracker.affects.all().values_list("flaw__cve_id", flat=True)
        self._query["fields"]["labels"] = {
            *cve_ids,
            "SecurityTracking",
            "Security",
            f"pscomponent:{self.ps_component}",
        }

    def generate_summary(self):
        """
        Generates the summary of a tracker
        """
        # TODO support multi-flaw tracker
        flaw = self.tracker.affects.filter(flaw__cve_id__isnull=False).first().flaw
        cve_id = flaw.cve_id + " "
        if not flaw:
            flaw = self.tracker.affects[0].flaw
            cve_id = ""
        self._query["fields"]["summary"] = (
            f"{cve_id}{self.ps_component}: "
            f"{flaw.title} [{self.tracker.ps_update_stream}]"
        )
