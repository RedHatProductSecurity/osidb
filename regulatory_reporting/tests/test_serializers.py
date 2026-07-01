import pytest

from regulatory_reporting.serializers import (
    FlawUpstreamMappingSerializer,
    UpstreamNotificationSerializer,
    UpstreamProjectSerializer,
)
from regulatory_reporting.tests.factories import (
    FlawUpstreamMappingFactory,
    UpstreamNotificationFactory,
    UpstreamProjectFactory,
)


class TestUpstreamProjectSerializer:
    def test_fields(self):
        fields = UpstreamProjectSerializer().fields.keys()
        assert "uuid" in fields
        assert "component_name" in fields
        assert "repository_url" in fields
        assert "created_dt" in fields
        assert "updated_dt" in fields

    @pytest.mark.django_db
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

    @pytest.mark.django_db
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

    @pytest.mark.django_db
    def test_serializes_instance(self):
        mapping = FlawUpstreamMappingFactory()
        data = FlawUpstreamMappingSerializer(mapping).data
        assert data["upstream_project"] == mapping.upstream_project.uuid
        assert data["notes"] == mapping.notes
