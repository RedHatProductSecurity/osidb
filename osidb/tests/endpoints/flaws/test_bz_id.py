import pytest

from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("api_version", ["v1", "v2"])
@pytest.mark.parametrize("detail", [False, True])
@pytest.mark.parametrize("include_meta_attr", ["bz_id", "*"])
@pytest.mark.parametrize("legacy_metadata", [{}, {"bz_id": None}, {"bz_id": "654321"}])
def test_legacy_bz_id_response_alias(
    auth_client, test_api_uri, detail, include_meta_attr, legacy_metadata
):
    """Derive the requested legacy string ID without changing stored metadata."""
    metadata = {"other": "keep", **legacy_metadata}
    flaw = FlawFactory(bz_id=123456, meta_attr=metadata)
    path = f"{test_api_uri}/flaws"
    if detail:
        path += f"/{flaw.uuid}"

    response = auth_client().get(f"{path}?include_meta_attr={include_meta_attr}")

    assert response.status_code == 200
    body = response.json() if detail else response.json()["results"][0]
    expected_metadata = {"bz_id": "123456"}
    if include_meta_attr == "*":
        expected_metadata["other"] = "keep"
    assert body["bz_id"] == 123456
    assert body["meta_attr"] == expected_metadata
    flaw.refresh_from_db()
    assert flaw.meta_attr == metadata
