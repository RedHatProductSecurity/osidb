"""
Jira tracker query generation module
"""
import json
import logging
from functools import cached_property

from apps.sla.framework import SLAFramework
from apps.trackers.common import TrackerQueryBuilder
from apps.trackers.exceptions import NoPriorityAvailableError
from apps.trackers.models import JiraProjectFields
from osidb.models import Affect, Impact
from osidb.validators import CVE_RE_STR

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
        self.generate_description()
        self.generate_labels()
        self.generate_sla()
        self.generate_summary()
        self.generate_versions()

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
        for priority in IMPACT_TO_JIRA_PRIORITY[self.impact]:
            if priority in allowed_values:
                self._query["fields"]["priority"] = {"name": priority}
                return

        raise NoPriorityAvailableError(
            f"Jira project {self.ps_module.bts_key} does not have a corresponding priority for impact "
            f"{self.impact}; allowed Jira priority values are: {', '.join(allowed_values)}"
        )

    def generate_description(self):
        """
        generates query for the tracker description
        """
        self._query["fields"]["description"] = self.description

    def generate_labels(self):
        """
        generate query for Jira labels
        """

        all_existing_labels = json.loads(self.tracker.meta_attr.get("labels", "[]"))

        # These labels are from elsewhere than this method and preserved with their ordering intact.
        # Because the engineering may use them.
        labels_to_preserve = [
            lbl
            for lbl in all_existing_labels
            if not (
                # Labels matching this condition will be recreated as needed.
                lbl.startswith("pscomponent:")
                or lbl in ["SecurityTracking", "Security", "validation-requested"]
                or CVE_RE_STR.match(lbl)
            )
        ]

        self._query["fields"]["labels"] = [
            *labels_to_preserve,
            "SecurityTracking",
            "Security",
            f"pscomponent:{self.ps_component}",
            *list(  # add all linked non-empty CVE IDs
                self.tracker.affects.exclude(flaw__cve_id__isnull=True).values_list(
                    "flaw__cve_id", flat=True
                )
            ),
        ]

        # If all affects are NEW, add label validation-requested.
        if set(self.tracker.affects.all().values_list("affectedness", flat=True)) == {
            Affect.AffectAffectedness.NEW
        }:
            self._query["fields"]["labels"].append("validation-requested")

        # If at least one affect has is_contract_priority, add label contract-priority
        for affect in self.tracker.affects.all():
            if affect.is_contract_priority:
                self._query["fields"]["labels"].append("contract-priority")
                break

    def generate_sla(self):
        """
        generate query for Jira SLA timestamps
        """
        sla_framework = SLAFramework()
        sla_context = sla_framework.classify(self.tracker)
        # the tracker may or may not be under SLA
        if sla_context.sla is not None:
            self._query["fields"]["duedate"] = sla_context.end.isoformat()
            # check that Target start field is present
            # and eventually get its custom field ID
            target_start = JiraProjectFields.objects.filter(
                project_key=self.ps_module.bts_key, field_name="Target start"
            )
            if target_start.exists():
                self._query["fields"][
                    target_start.first().field_id
                ] = sla_context.start.isoformat()

    def generate_summary(self):
        """
        Generates the summary of a tracker
        """
        self._query["fields"]["summary"] = self.summary

    def generate_versions(self):
        """
        generates the versions
        """
        versions = JiraProjectFields.objects.filter(
            project_key=self.ps_module.bts_key, field_name="Affects Version/s"
        )
        # project may or may not support versions so it is optional
        if versions.exists() and self.ps_update_stream.version is not None:
            self._query["fields"]["versions"] = [
                {"name": self.ps_update_stream.version}
            ]
