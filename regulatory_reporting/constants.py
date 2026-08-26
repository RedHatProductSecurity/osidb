"""Shared constants for regulatory reporting."""

from regulatory_reporting.models import SRPReport, SRPReportMilestone

# UUID path segment for DRF router nested kwargs and lookup_value_regex.
UUID_PATH_REGEX = (
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


# Basic milestones types for KEV and severe-incident reports.
BASIC_MILESTONES_TYPES = [
    SRPReportMilestone.MilestoneType.LEVEL_24H,
    SRPReportMilestone.MilestoneType.LEVEL_72H,
    SRPReportMilestone.MilestoneType.LEVEL_FINAL,
]

# Milestones types for additional-information-request reports.
ADDITIONAL_MILESTONES_TYPES = [
    SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE
]

MILESTONES_TYPES_BY_REPORTABLE_EVENT_TYPE = {
    SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED: BASIC_MILESTONES_TYPES,
    SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED: BASIC_MILESTONES_TYPES,
}
