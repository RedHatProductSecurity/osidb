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
    TrackingMixin,
    TrackingMixinManager,
    validator,
)

from .abstracts import SRPReportBase
from .srp_report import SRPReport


class SRPReportMilestoneManager(TrackingMixinManager):
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

    class SRPReportMilestoneStatus(models.TextChoices):
        """Status of the SRP report milestone"""

        # Required (default), In progress, In review, Submitted, Obsolete
        REQUIRED = "required", "Required"
        IN_PROGRESS = "in_progress", "In Progress"
        IN_REVIEW = "in_review", "In Review"
        SUBMITTED = "submitted", "Submitted"
        OBSOLETE = "obsolete", "Obsolete"

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
        choices=SRPReportMilestoneStatus.choices,
        max_length=20,
        default=SRPReportMilestoneStatus.REQUIRED,
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
        - KEV (EXPLOITS_KEV_APPROVED): 14 days
        - Severe Incident (MAJOR_INCIDENT_APPROVED): 30 days
        - Additional Information Request: 30 days from the request received
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
                == SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED
            ):
                duration = timedelta(days=14)
            elif (
                self.srp_report.reportable_event_type
                == SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED
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

    def save(self, *args, **kwargs):
        """
        Persist the milestone, and prepare the SRP payload snapshot when
        status transitions to SUBMITTED for builder-backed milestone types.
        """
        if getattr(self, "_preparing_payload", False):
            return super().save(*args, **kwargs)

        previous_status = None
        if self.pk:
            previous_status = (
                type(self)
                .objects.filter(pk=self.pk)
                .values_list("status", flat=True)
                .first()
            )

        super().save(*args, **kwargs)

        should_prepare = (
            self.status == self.SRPReportMilestoneStatus.SUBMITTED
            and previous_status != self.SRPReportMilestoneStatus.SUBMITTED
            and self.milestone_type
            in {
                self.MilestoneType.LEVEL_24H,
                self.MilestoneType.LEVEL_72H,
                self.MilestoneType.LEVEL_FINAL,
            }
        )
        if should_prepare:
            # Lazy import avoids circular dependency with services.py
            from regulatory_reporting.services import prepare_payload

            prepare_payload(self)
            self._preparing_payload = True
            try:
                # force_insert must not carry over: the row was already
                # inserted/updated above, so this second save is always an
                # update.
                save_kwargs = {**kwargs, "force_insert": False}
                if save_kwargs.get("update_fields") is not None:
                    save_kwargs["update_fields"] = list(
                        save_kwargs["update_fields"]
                    ) + ["meta_attr", "missing_required_fields"]
                super().save(*args, **save_kwargs)
            finally:
                self._preparing_payload = False

    @validator
    def _validate_due_at_required(self, **kwargs):
        """
        Due date must be set for all milestones.

        Exceptions:
        - LEVEL_ADDITIONAL_INFORMATION_RESPONSE can have None due_at if
          request_received_at is not yet set.
        - REQUIRED milestones can have None due_at until the parent
          report's SLA timer starts.
        """
        if (
            self.milestone_type == self.MilestoneType.LEVEL_FINAL
            and self.srp_report.reportable_event_type
            not in {
                SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED,
                SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
            }
            and self.status != self.SRPReportMilestoneStatus.REQUIRED
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
            # Allow None while manually created reports wait for timer start
            if self.status == self.SRPReportMilestoneStatus.REQUIRED:
                return
            raise ValidationError("due_at must be set for all milestones")
