"""
CRA (Cyber Resilience Act) Regulatory Reporting SRP Report Milestone model.

This module contains models for managing SRP (Single Reporting Platform)
milestones as required by the EU Cyber Resilience Act.
"""

from datetime import timedelta

import pghistory
from django.contrib.postgres.indexes import GinIndex
from django.core.exceptions import ValidationError
from django.db import models
from psqlextra.fields import HStoreField

from osidb.mixins import (
    ACLMixinManager,
    TrackingMixin,
    TrackingMixinManager,
    validator,
)

from .abstracts import SRPReportBase
from .srp_report import SRPReport


class SRPReportMilestoneManager(ACLMixinManager, TrackingMixinManager):
    """SRP Report Milestone manager"""

    pass


@pghistory.track(
    pghistory.InsertEvent(),
    pghistory.UpdateEvent(),
    pghistory.DeleteEvent(),
    exclude="meta_attr",
    model_name="SRPReportMilestoneAudit",
)
class SRPReportMilestone(SRPReportBase):
    """
    Model for tracking individual SRP report milestones/deadlines.

    Represents specific submission deadlines (24h early warning, 72h notification,
    final report) for an SRP report, each with their own ENISA template and payload.
    """

    class MilestoneType(models.TextChoices):
        """Milestone type level for this milestone"""

        LEVEL_24H = "24h", "24 Hour Template"
        LEVEL_72H = "72h", "72 Hour Template"
        LEVEL_FINAL = "final", "Final Report Template"
        LEVEL_ADDITIONAL_INFORMATION_RESPONSE = (
            "additional_information_response",
            "Additional Information Response Template",
        )

    MILESTONE_DURATION_BY_TYPE = {
        MilestoneType.LEVEL_24H: timedelta(hours=24),
        MilestoneType.LEVEL_72H: timedelta(hours=72),
        MilestoneType.LEVEL_FINAL: None,  # Duration is calculated based on the reportable event type
        MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE: timedelta(days=30),
    }

    # Foreign key to parent SRP report
    srp_report = models.ForeignKey(
        SRPReport,
        on_delete=models.CASCADE,
        related_name="milestones",
        help_text="The SRP report this milestone belongs to",
    )

    # Milestone classification
    milestone_type = models.CharField(
        choices=MilestoneType.choices,
        max_length=50,
        help_text="Type of milestone (24h, 72h, final, etc.)",
    )

    request_received_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the request was received",
    )
    request_source = models.CharField(
        max_length=255,
        blank=True,
        help_text="Source of the request",
    )
    request_text = models.TextField(
        blank=True,
        help_text="Text of the request",
    )

    status = models.CharField(
        choices=SRPReportBase.SRPReportStatus.choices,
        max_length=20,
        default=SRPReportBase.SRPReportStatus.REQUIRED,
        help_text="Current status of the milestone",
    )

    # Non-operational metadata
    meta_attr = HStoreField(default=dict)

    class Meta:
        """Model metadata"""

        verbose_name = "SRP Report Milestone"
        verbose_name_plural = "SRP Report Milestones"
        ordering = ("srp_report", "created_dt")

        indexes = TrackingMixin.Meta.indexes + [
            models.Index(fields=["srp_report"]),
            models.Index(fields=["milestone_type"]),
            models.Index(fields=["status"]),
            GinIndex(fields=["acl_read"]),
        ]

        constraints = [
            models.UniqueConstraint(
                fields=["srp_report", "milestone_type"],
                condition=~models.Q(milestone_type="additional_information_response"),
                name="unique_srp_report_milestone_type_level",
            )
        ]

    objects = SRPReportMilestoneManager()

    @property
    def due_at(self):
        """
        Calculate milestone due date.

        For LEVEL_FINAL: duration depends on event type:
        - KEV (actively_exploited_vulnerability): 14 days
        - Severe Incident (severe_incident): 30 days
        - Additional Information Request (additional_information_request): 30 days from the request received
        """
        if (
            self.milestone_type
            == self.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE
        ):
            if not self.request_received_at:
                return None
            return self.request_received_at + timedelta(days=30)

        if not self.srp_report.timer_started_at:
            return None

        if self.milestone_type == self.MilestoneType.LEVEL_FINAL:
            # Check parent report's event type
            if (
                self.srp_report.reportable_event_type
                == SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY
            ):
                duration = timedelta(days=14)
            elif (
                self.srp_report.reportable_event_type
                == SRPReport.ReportableEventType.SEVERE_INCIDENT
            ):
                duration = timedelta(days=30)
            else:
                return None
        else:
            # Use static duration for 24h, 72h, etc.
            duration = self.MILESTONE_DURATION_BY_TYPE[self.milestone_type]

        return self.srp_report.timer_started_at + duration

    def __str__(self):
        return f"{self.milestone_type} - {self.srp_report.flaw.cve_id or self.srp_report.flaw.uuid}"

    @validator
    def _validate_due_at_required(self, **kwargs):
        """
        Due date must be set for all milestones.

        Exception: LEVEL_ADDITIONAL_INFORMATION_RESPONSE milestones can have
        None due_at if request_received_at is not yet set.
        """
        if (
            self.milestone_type == self.MilestoneType.LEVEL_FINAL
            and self.srp_report.reportable_event_type
            not in {
                SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY,
                SRPReport.ReportableEventType.SEVERE_INCIDENT,
            }
        ):
            raise ValidationError("Invalid reportable event type")

        if not self.due_at:
            # Allow None for additional info milestones without request time
            if (
                self.milestone_type
                == self.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE
                and not self.request_received_at
            ):
                return  # Valid state - waiting for request
            raise ValidationError("due_at must be set for all milestones")
