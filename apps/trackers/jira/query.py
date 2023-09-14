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
        self._query = None

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
        generates query for the tracker description
        """
        self._query["fields"]["description"] = self.description

    # TODO we should not delete other labels
    # because the engineeting may use them
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
        self._query["fields"]["summary"] = self.summary
