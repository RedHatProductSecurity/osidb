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

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    missing_required_fields = models.TextField(
        blank=True, help_text="Missing required fields"
    )

    manual_completion_notes = models.TextField(
        blank=True, help_text="Manual completion notes"
    )

    class Meta:
        abstract = True
