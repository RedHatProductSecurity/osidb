import pytest
from rest_framework import status

from osidb.models.abstract import Impact


@pytest.mark.django_db
@pytest.mark.parametrize(
    "path,query_params",
    [
        (
            "/component-mapping/pre-filter",
            {"component": "openssl"},
        ),
        (
            "/affects/auto-resolve",
            {
                "ps_update_stream": "any-stream",
                "impact": Impact.IMPORTANT,
            },
        ),
        (
            "/ps-modules/active-streams",
            {"names": "openshift-4"},
        ),
    ],
)
def test_ace_api_requires_authentication(client, test_api_uri, path, query_params):
    response = client.get(f"{test_api_uri}{path}", query_params)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
