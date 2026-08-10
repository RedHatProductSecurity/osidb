"""
CRA (Cyber Resilience Act) Regulatory Reporting models.

This module contains models for managing SRP (Single Reporting Platform)
reports and upstream notifications as required by the EU Cyber Resilience Act.
"""

import uuid
from datetime import timedelta

from django.db import models

from osidb.mixins import (
    ACLMixin,
    AlertMixin,
    NullStrFieldsMixin,
    TrackingMixin,
)


class SRPReportBase(
    AlertMixin, TrackingMixin, NullStrFieldsMixin, ACLMixin, models.Model
):
    """Base model for SRP report or milestone"""

    class SRPReportStatus(models.TextChoices):
        """Status of the SRP report or milestone"""

        # NOTE: when moving or renaming this enum, please check and modify
        # config/settings.py::SPECTACULAR_SETTINGS::ENUM_NAME_OVERRIDES accordingly

        NOT_APPLICABLE = "not_applicable", "Not Applicable"
        NOT_REQUIRED = "not_required", "Not Required"
        PRE_REQUIRED = "pre_required", "Pre Required"
        REQUIRED = "required", "Required"
        PREPARED = "prepared", "Prepared"
        SUBMITTED = "submitted", "Submitted"
        DEFERRED = "deferred", "Deferred"
        BLOCKED = "blocked", "Blocked"
        FAILED = "failed", "Failed"

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

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    missing_required_fields = models.TextField(
        blank=True, help_text="Missing required fields"
    )

    manual_completion_notes = models.TextField(
        blank=True, help_text="Manual completion notes"
    )

    class Meta:
        abstract = True
