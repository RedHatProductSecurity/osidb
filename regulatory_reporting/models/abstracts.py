"""
CRA (Cyber Resilience Act) Regulatory Reporting models.

This module contains models for managing SRP (Single Reporting Platform)
reports and upstream notifications as required by the EU Cyber Resilience Act.
"""

import uuid

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

        NOT_APPLICABLE = "not_applicable", "Not Applicable"
        NOT_REQUIRED = "not_required", "Not Required"
        REQUIRED = "required", "Required"
        PREPARED = "prepared", "Prepared"
        SUBMITTED = "submitted", "Submitted"
        DEFERRED = "deferred", "Deferred"
        BLOCKED = "blocked", "Blocked"
        FAILED = "failed", "Failed"

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    missing_required_fields = models.TextField(
        blank=True, help_text="Missing required fields"
    )

    manual_completion_notes = models.TextField(
        blank=True, help_text="Manual completion notes"
    )

    class Meta:
        abstract = True
