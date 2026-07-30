import uuid

from regulatory_reporting.models.upstream import FlawUpstreamMapping

from .factories import (
    FlawUpstreamMappingFactory,
    UpstreamProjectFactory,
)

FLAW_UPSTREAM_MAPPINGS_URI = "/regulatory-reporting/api/v1/flaws"
FLAW_UPSTREAM_MAPPING_DETAIL_URI = "/regulatory-reporting/api/v1/flaw-upstream-mappings"


class TestFlawUpstreamMappingListCreateView:
    def test_list_mappings_for_flaw(self, auth_client):
        mapping = FlawUpstreamMappingFactory()
        FlawUpstreamMappingFactory(flaw=mapping.flaw)
        FlawUpstreamMappingFactory()  # different flaw, should not appear

        response = auth_client().get(
            f"{FLAW_UPSTREAM_MAPPINGS_URI}/{mapping.flaw.uuid}/upstream-mappings"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 2

    def test_list_mappings_flaw_not_found(self, auth_client):
        response = auth_client().get(
            f"{FLAW_UPSTREAM_MAPPINGS_URI}/{uuid.uuid4()}/upstream-mappings"
        )
        assert response.status_code == 404

    def test_create_mapping(self, auth_client):
        flaw = FlawUpstreamMappingFactory().flaw
        project = UpstreamProjectFactory()

        response = auth_client().post(
            f"{FLAW_UPSTREAM_MAPPINGS_URI}/{flaw.uuid}/upstream-mappings",
            data={"upstream_project": str(project.uuid), "notes": "test note"},
            format="json",
        )
        assert response.status_code == 201
        assert response.json()["flaw_uuid"] == str(flaw.uuid)

    def test_create_mapping_flaw_not_found(self, auth_client):
        project = UpstreamProjectFactory()

        response = auth_client().post(
            f"{FLAW_UPSTREAM_MAPPINGS_URI}/{uuid.uuid4()}/upstream-mappings",
            data={"upstream_project": str(project.uuid), "notes": "test"},
            format="json",
        )
        assert response.status_code == 404


class TestFlawUpstreamMappingDetailView:
    def test_put_mapping_notes(self, auth_client):
        mapping = FlawUpstreamMappingFactory(notes="original")

        response = auth_client().put(
            f"{FLAW_UPSTREAM_MAPPING_DETAIL_URI}/{mapping.uuid}",
            data={
                "upstream_project": str(mapping.upstream_project.uuid),
                "notes": "updated",
                "updated_dt": mapping.updated_dt.isoformat(),
            },
            format="json",
        )
        assert response.status_code == 200
        mapping.refresh_from_db()
        assert mapping.notes == "updated"

    def test_put_mapping_not_found(self, auth_client):
        response = auth_client().put(
            f"{FLAW_UPSTREAM_MAPPING_DETAIL_URI}/{uuid.uuid4()}",
            data={"notes": "updated"},
            format="json",
        )
        assert response.status_code == 404

    def test_delete_mapping(self, auth_client):
        mapping = FlawUpstreamMappingFactory()

        response = auth_client().delete(
            f"{FLAW_UPSTREAM_MAPPING_DETAIL_URI}/{mapping.uuid}"
        )
        assert response.status_code == 204
        assert not FlawUpstreamMapping.objects.filter(uuid=mapping.uuid).exists()

    def test_delete_mapping_not_found(self, auth_client):
        response = auth_client().delete(
            f"{FLAW_UPSTREAM_MAPPING_DETAIL_URI}/{uuid.uuid4()}"
        )
        assert response.status_code == 404

    def test_get_not_allowed_on_detail(self, auth_client):
        mapping = FlawUpstreamMappingFactory()

        response = auth_client().get(
            f"{FLAW_UPSTREAM_MAPPING_DETAIL_URI}/{mapping.uuid}"
        )
        assert response.status_code == 405
