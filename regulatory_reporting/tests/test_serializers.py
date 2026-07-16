"""
Tests for regulatory reporting serializers.
"""

from datetime import timedelta

import pytest
from django.utils import timezone

from osidb.models import Flaw
from osidb.tests.factories import FlawFactory
from regulatory_reporting.models import SRPReport, SRPReportMilestone
from regulatory_reporting.serializers import (
    FlawUpstreamMappingSerializer,
    SRPReportMilestoneSerializer,
    SRPReportSerializer,
    UpstreamNotificationSerializer,
    UpstreamProjectSerializer,
)
from regulatory_reporting.tests.factories import (
    FlawUpstreamMappingFactory,
    UpstreamNotificationFactory,
    UpstreamProjectFactory,
)

pytestmark = [pytest.mark.unit, pytest.mark.enable_signals]


class TestUpstreamProjectSerializer:
    def test_fields(self):
        fields = UpstreamProjectSerializer().fields.keys()
        assert "uuid" in fields
        assert "component_name" in fields
        assert "repository_url" in fields
        assert "created_dt" in fields
        assert "updated_dt" in fields

    def test_serializes_instance(self):
        project = UpstreamProjectFactory()
        data = UpstreamProjectSerializer(project).data
        assert data["component_name"] == project.component_name
        assert data["repository_url"] == project.repository_url
        assert str(project.uuid) == data["uuid"]


class TestUpstreamNotificationSerializer:
    def test_fields(self):
        fields = UpstreamNotificationSerializer().fields.keys()
        assert "status" in fields
        assert "flaw_uuid" in fields
        assert "embargoed" in fields
        assert "visibility" in fields
        assert "created_dt" in fields

    def test_serializes_instance(self):
        notification = UpstreamNotificationFactory()
        data = UpstreamNotificationSerializer(notification).data
        assert data["status"] == notification.status
        assert data["upstream_project"] == notification.upstream_project.uuid


class TestFlawUpstreamMappingSerializer:
    def test_fields(self):
        fields = FlawUpstreamMappingSerializer().fields.keys()
        assert "flaw_uuid" in fields
        assert "upstream_project" in fields

    def test_serializes_instance(self):
        mapping = FlawUpstreamMappingFactory()
        data = FlawUpstreamMappingSerializer(mapping).data
        assert data["upstream_project"] == mapping.upstream_project.uuid
        assert data["notes"] == mapping.notes


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
        (due_at, hours_remaining, is_overdue).
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
        assert "hours_remaining" in data
        assert "is_overdue" in data

        # Verify values
        assert data["due_at"] is not None
        assert isinstance(data["hours_remaining"], int)
        assert data["hours_remaining"] == 23
        assert data["is_overdue"] is False


class TestSRPReportSerializer:
    """Test SRPReport serializer"""

    @pytest.mark.enable_signals
    def test_srp_report_serialization_severe_incident(self):
        """
        Test serialization of a Severe Incident report.

        Verifies reportable_event_type, milestone count, and final milestone deadline.
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
        assert len(data["milestones"]) == 3

        final_milestone_obj = srp_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL
        )
        assert final_milestone_obj.due_at == srp_report.timer_started_at + timedelta(
            days=30
        )

        final_milestone = next(
            m for m in data["milestones"] if m["milestone_type"] == "final"
        )
        expected_final = SRPReportMilestoneSerializer(final_milestone_obj).data
        assert final_milestone["due_at"] == expected_final["due_at"]
        assert final_milestone["hours_remaining"] == expected_final["hours_remaining"]
        assert final_milestone["days_remaining"] == expected_final["days_remaining"]
        # assert milestones are in order
        assert data["milestones"] == sorted(
            data["milestones"], key=lambda x: x["milestone_type"]
        )
        assert data["milestones"][0]["milestone_type"] == "24h"
        assert data["milestones"][0]["hours_remaining"] == 23
        assert data["milestones"][0]["days_remaining"] == 0
        assert data["milestones"][1]["milestone_type"] == "72h"
        assert data["milestones"][1]["hours_remaining"] == 71
        assert data["milestones"][1]["days_remaining"] == 2
        assert data["milestones"][2]["milestone_type"] == "final"
        assert data["milestones"][2]["hours_remaining"] == 30 * 24 - 1
        assert data["milestones"][2]["days_remaining"] == 29
