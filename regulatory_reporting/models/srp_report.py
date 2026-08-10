"""
CRA (Cyber Resilience Act) Regulatory Reporting SRP Report model.

This module contains models for managing SRP (Single Reporting Platform)
reports as required by the EU Cyber Resilience Act.
"""

import pghistory
from django.contrib.postgres import fields
from django.contrib.postgres.indexes import GinIndex
from django.core.exceptions import ValidationError
from django.db import models
from psqlextra.fields import HStoreField

from osidb.mixins import (
    TrackingMixin,
    TrackingMixinManager,
    validator,
)
from osidb.models.flaw.flaw import Flaw

from .abstracts import SRPReportBase


class SRPReportManager(TrackingMixinManager):
    """SRP Report manager"""

    pass


@pghistory.track(
    pghistory.InsertEvent(),
    pghistory.UpdateEvent(),
    pghistory.DeleteEvent(),
    exclude="meta_attr",
    model_name="SRPReportAudit",
)
class SRPReport(SRPReportBase):
    """
    Model for tracking SRP (Single Reporting Platform) reports.

    Represents a report that must be submitted to ENISA/CSIRT via the SRP
    for vulnerabilities (KEV) or incidents affecting Red Hat products or
    stewarded projects.
    """

    class ResponsibilityScope(models.TextChoices):
        """Red Hat's responsibility scope for the report"""

        MANUFACTURER = "manufacturer", "Manufacturer"
        STEWARD = "steward", "Steward"

    class ReportableEventType(models.TextChoices):
        """
        Type of reportable event according to CRA.

        Auto-created values match Flaw.FlawMajorIncident so signals can use
        major_incident_state directly without a mapping table.
        ADDITIONAL_INFORMATION_REQUEST is CRA-only (no Flaw counterpart).
        """

        EXPLOITS_KEV_APPROVED = (
            Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            "Actively Exploited Vulnerability",
        )
        MAJOR_INCIDENT_APPROVED = (
            Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
            "Severe Incident",
        )
        ADDITIONAL_INFORMATION_REQUEST = (
            "ADDITIONAL_INFORMATION_REQUEST",
            "Additional Information Request",
        )

        @classmethod
        def enisa_notification_type(cls, value: str) -> str:
            """Return the ENISA notification_type for a reportable_event_type value."""
            return cls(value).label.lower().replace(" ", "_")

    flaw = models.ForeignKey(
        Flaw,
        on_delete=models.PROTECT,
        related_name="srp_reports",
        help_text="The flaw for which this SRP report is being created",
    )

    # TextField to match Flaw.title (unbounded); report title is copied from the flaw
    title = models.TextField(help_text="Title of the SRP report")

    manufacturer_or_steward_name = models.CharField(
        max_length=255,
        help_text="Name of the manufacturer or steward",
        blank=True,
    )

    # Report classification
    responsibility_scope = models.CharField(
        choices=ResponsibilityScope.choices,
        max_length=20,
        help_text="Whether Red Hat acts as manufacturer or steward",
    )
    reportable_event_type = models.CharField(
        choices=ReportableEventType.choices,
        max_length=50,
        help_text="Type of event being reported to ENISA",
    )

    evidence = models.TextField(
        blank=True,
        help_text=(
            "Justification for manually creating this SRP report when automatic "
            "criteria were not met"
        ),
    )

    # SLA tracking
    timer_started_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the SLA clock started for this report",
    )

    # SRP integration
    srp_reference_id = models.CharField(
        max_length=255,
        blank=True,
        help_text="Reference ID returned by the SRP after submission",
    )

    srp_reference_url = models.URLField(
        max_length=200,
        blank=True,
        help_text="URL of the SRP reference",
    )

    member_states_available = fields.ArrayField(
        models.CharField(max_length=2),
        default=list,
        blank=True,
        help_text="List of EU member state codes where product is available",
    )

    designated_csirt_country = models.CharField(
        max_length=2,
        blank=True,
        help_text="Country code of the designated CSIRT coordinator",
    )

    designated_csirt_source = models.CharField(
        max_length=255,
        blank=True,
        help_text="Source of the designated CSIRT coordinator",
    )

    # Non-operational metadata
    meta_attr = HStoreField(default=dict)

    class Meta:
        verbose_name = "SRP Report"
        verbose_name_plural = "SRP Reports"
        ordering = ("created_dt", "uuid", "timer_started_at")

        indexes = TrackingMixin.Meta.indexes + [
            models.Index(fields=["flaw"]),
            models.Index(fields=["timer_started_at"]),
            models.Index(fields=["reportable_event_type"]),
            models.Index(fields=["responsibility_scope"]),
            GinIndex(fields=["acl_read"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["flaw", "reportable_event_type"],
                name="unique_srp_report_flaw_event_type",
            ),
        ]

    objects = SRPReportManager()

    def __str__(self):
        return f"SRP Report {self.uuid} for {self.flaw.cve_id or self.flaw.uuid}"

    ACTIVE_MILESTONE_STATUSES = (
        SRPReportBase.SRPReportStatus.PRE_REQUIRED,
        SRPReportBase.SRPReportStatus.REQUIRED,
        SRPReportBase.SRPReportStatus.PREPARED,
    )

    STANDARD_MILESTONE_TYPES = (
        SRPReportBase.MilestoneType.LEVEL_24H,
        SRPReportBase.MilestoneType.LEVEL_72H,
        SRPReportBase.MilestoneType.LEVEL_FINAL,
    )

    def _status_suffix(self):
        """Return the milestone-status half of the derived `{type}:{status}` value."""
        if not self.status or ":" not in self.status:
            return None
        return self.status.split(":", 1)[1]

    @validator
    def _validate_timer_started_required(self, **kwargs):
        """Timer must be set when status transitions to REQUIRED or beyond"""
        if (
            self._status_suffix()
            in [
                SRPReportBase.SRPReportStatus.REQUIRED,
                SRPReportBase.SRPReportStatus.PREPARED,
                SRPReportBase.SRPReportStatus.SUBMITTED,
            ]
            and not self.timer_started_at
        ):
            raise ValidationError(
                "timer_started_at must be set when status is REQUIRED, PREPARED, or SUBMITTED"
            )

    @validator
    def _validate_evidence_required(self, **kwargs):
        """Evidence is required for manually created (PRE_REQUIRED) reports"""
        if self._status_suffix() == SRPReportBase.SRPReportStatus.PRE_REQUIRED and (
            not self.evidence or not self.evidence.strip()
        ):
            raise ValidationError("evidence must be set when status is PRE_REQUIRED")

    @validator
    def _validate_srp_reference_required(self, **kwargs):
        """SRP reference ID must be set when status is SUBMITTED"""
        if (
            self._status_suffix() == SRPReportBase.SRPReportStatus.SUBMITTED
            and not self.srp_reference_id
        ):
            raise ValidationError(
                "srp_reference_id must be set when status is SUBMITTED"
            )

    def _get_last_active_milestone(self):
        """
        Milestone that drives the derived report status.

        Prefer the first active milestone (PRE_REQUIRED/REQUIRED/PREPARED)
        in priority order:
        24h → 72h → final → earliest additional_information_response
        (by request_received_at).

        If none are active, fall back to the furthest milestone in the pipeline:
        latest additional_information_response → final → 72h → 24h.
        """
        milestones = list(self.milestones.all())
        active = [m for m in milestones if m.status in self.ACTIVE_MILESTONE_STATUSES]

        for milestone_type in self.STANDARD_MILESTONE_TYPES:
            for milestone in active:
                if milestone.milestone_type == milestone_type:
                    return milestone

        active_additionals = [
            m
            for m in active
            if m.milestone_type
            == self.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE
        ]
        active_additionals.sort(
            key=lambda m: (
                m.request_received_at is None,
                m.request_received_at or m.created_dt,
            )
        )
        if active_additionals:
            return active_additionals[0]

        # No active milestones: furthest closed milestone in the pipeline.
        all_additionals = [
            m
            for m in milestones
            if m.milestone_type
            == self.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE
        ]
        if all_additionals:
            dated = [m for m in all_additionals if m.request_received_at is not None]
            if dated:
                # Tie-break with newer created_dt to match filter ordering.
                return max(dated, key=lambda m: (m.request_received_at, m.created_dt))
            return max(all_additionals, key=lambda m: m.created_dt)

        by_type = {m.milestone_type: m for m in milestones}
        for milestone_type in reversed(self.STANDARD_MILESTONE_TYPES):
            if milestone_type in by_type:
                return by_type[milestone_type]

        return None

    @property
    def status(self):
        last_active_milestone = self._get_last_active_milestone()
        if not last_active_milestone:
            return None
        return f"{last_active_milestone.milestone_type}:{last_active_milestone.status}"

    def active_due_at(self):
        """Return the due date for the active milestone"""
        last_active_milestone = self._get_last_active_milestone()
        if not last_active_milestone:
            return None
        return last_active_milestone.due_at
