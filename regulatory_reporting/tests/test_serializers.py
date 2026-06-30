"""
Tests for SRP Report and Milestone serializers.

OSIDB-5072: Add SRP Serializers
"""

from datetime import timedelta

import pytest
from django.utils import timezone

from osidb.models import Flaw
from osidb.tests.factories import FlawFactory
from regulatory_reporting.models import SRPReport, SRPReportMilestone
from regulatory_reporting.serializers import (
    SRPReportMilestoneSerializer,
    SRPReportSerializer,
)

pytestmark = pytest.mark.unit


class TestSRPReportMilestoneSerializer:
    """Test SRPReportMilestone serializer"""

    @pytest.mark.enable_signals
    def test_milestone_serialization_basic_fields(self):
        """
        Test that milestone serializer includes all basic fields.
        """
        # Arrange
        start_time = timezone.now()
        flaw = FlawFactory(
            cve_id="CVE-2024-1234",
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )
        srp_report = SRPReport.objects.get(flaw=flaw)
        milestone = srp_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        # Act
        serializer = SRPReportMilestoneSerializer(milestone)
        data = serializer.data

        # Assert - basic fields present
        assert "uuid" in data
        assert "srp_report" in data
        assert "milestone_type" in data
        assert data["milestone_type"] == "24h"
        assert "status" in data
        assert data["status"] == "required"
        assert "created_dt" in data
        assert "updated_dt" in data

    @pytest.mark.enable_signals
    def test_milestone_serialization_computed_fields(self):
        """
        Test that milestone serializer includes computed fields
        (due_at, days_remaining, is_overdue).
        """
        # Arrange
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )
        srp_report = SRPReport.objects.get(flaw=flaw)
        milestone = srp_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        # Act
        serializer = SRPReportMilestoneSerializer(milestone)
        data = serializer.data

        # Assert - computed fields present
        assert "due_at" in data
        assert "days_remaining" in data
        assert "is_overdue" in data

        # Verify values
        assert data["due_at"] is not None
        assert isinstance(data["days_remaining"], int)
        assert data["days_remaining"] == 0  # Due in ~24 hours, rounds to 0 days
        assert data["is_overdue"] is False

    @pytest.mark.enable_signals
    def test_milestone_serialization_acl_fields(self):
        """
        Test that milestone serializer includes ACL fields.
        """
        # Arrange
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )
        srp_report = SRPReport.objects.get(flaw=flaw)
        milestone = srp_report.milestones.first()

        # Act
        serializer = SRPReportMilestoneSerializer(milestone)
        data = serializer.data

        # Assert - ACL fields present
        assert "acl_read" in data
        assert "acl_write" in data
        assert isinstance(data["acl_read"], list)
        assert isinstance(data["acl_write"], list)

    @pytest.mark.enable_signals
    def test_milestone_serialization_overdue_milestone(self):
        """
        Test that is_overdue is True for past-due milestones.
        """
        # Arrange - create milestone with past due date
        past_time = timezone.now() - timedelta(days=5)
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=past_time,
        )
        srp_report = SRPReport.objects.get(flaw=flaw)
        milestone = srp_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        # Act
        serializer = SRPReportMilestoneSerializer(milestone)
        data = serializer.data

        # Assert
        assert data["is_overdue"] is True
        assert data["days_remaining"] < 0  # Negative days = overdue


class TestSRPReportSerializer:
    """Test SRPReport serializer"""

    @pytest.mark.enable_signals
    def test_srp_report_serialization_basic_fields(self):
        """
        Test that SRP Report serializer includes all basic fields.
        """
        # Arrange
        start_time = timezone.now()
        flaw = FlawFactory(
            cve_id="CVE-2024-5678",
            title="Test vulnerability",
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )
        srp_report = SRPReport.objects.get(flaw=flaw)

        # Act
        serializer = SRPReportSerializer(srp_report)
        data = serializer.data

        # Assert - basic fields
        assert "uuid" in data
        assert "title" in data
        assert "responsibility_scope" in data
        assert data["responsibility_scope"] == "manufacturer"
        assert "reportable_event_type" in data
        assert data["reportable_event_type"] == "actively_exploited_vulnerability"
        assert "status" in data
        assert data["status"] == "required"
        assert "timer_started_at" in data

    @pytest.mark.enable_signals
    def test_srp_report_serialization_flaw_field(self):
        """
        Test that flaw field returns minimal representation (uuid ).
        """
        # Arrange
        start_time = timezone.now()
        flaw = FlawFactory(
            cve_id="CVE-2024-9999",
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )
        srp_report = SRPReport.objects.get(flaw=flaw)

        # Act
        serializer = SRPReportSerializer(srp_report)
        data = serializer.data

        # Assert
        assert "flaw" not in data
        assert "flaw_id" in data
        assert data["flaw_id"] == flaw.uuid

    @pytest.mark.enable_signals
    def test_srp_report_serialization_severe_incident(self):
        """
        Test serialization of Severe Incident report (different from KEV).
        """
        # Arrange
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
            major_incident_start_dt=start_time,
        )
        srp_report = SRPReport.objects.get(flaw=flaw)

        # Act
        serializer = SRPReportSerializer(srp_report)
        data = serializer.data

        # Assert - different event type
        assert data["reportable_event_type"] == "severe_incident"

        # Assert - final milestone has different duration (30 days vs 14 days)
        # Both have milestones
        assert len(data["milestones"]) == 3

    @pytest.mark.enable_signals
    def test_srp_report_serialization_no_meta_attr_field(self):
        """
        Test that meta_attr is omitted unless include_meta_attr is requested.
        """
        # Arrange
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )
        srp_report = SRPReport.objects.get(flaw=flaw)
        srp_report.meta_attr = {"srp_reference": "ext-123", "other_key": "value"}
        srp_report.save()

        # Act
        serializer = SRPReportSerializer(srp_report)
        data = serializer.data

        # Assert - meta_attr should not be in response by default
        assert "meta_attr" not in data

    @pytest.mark.enable_signals
    def test_srp_report_serialization_include_meta_attr(self):
        """
        Test that meta_attr is exposed when include_meta_attr is requested.
        """
        # Arrange
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )
        srp_report = SRPReport.objects.get(flaw=flaw)
        srp_report.meta_attr = {"srp_reference": "ext-123", "other_key": "value"}
        srp_report.save()

        # Act - filter to a single key
        serializer = SRPReportSerializer(
            srp_report, context={"include_meta_attr": ["srp_reference"]}
        )
        data = serializer.data

        # Assert
        assert data["meta_attr"] == {"srp_reference": "ext-123"}

        # Act - include all keys
        serializer = SRPReportSerializer(
            srp_report, context={"include_meta_attr": ["*"]}
        )
        data = serializer.data

        # Assert
        assert data["meta_attr"] == {
            "srp_reference": "ext-123",
            "other_key": "value",
        }
