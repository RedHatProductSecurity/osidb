import pytest

from osidb.hooks import response_metadata_postprocess_hook

pytestmark = pytest.mark.unit
METADATA_FIELDS = {"dt", "env", "revision", "version"}


def make_result():
    """
    minimal OpenAPI schema with three operations
    built fresh per test as the hook mutates its input
    """
    return {
        "paths": {
            "/fake/with-body": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object", "properties": {}}
                                }
                            },
                            "description": "",
                        }
                    }
                }
            },
            "/fake/bodyless-200": {"get": {"responses": {"200": {"description": ""}}}},
            "/fake/bodyless-204": {
                "delete": {"responses": {"204": {"description": ""}}}
            },
        }
    }


class TestResponseMetadataHook(object):
    def test_204_is_left_untouched(self):
        """
        204 No Content must not declare a JSON body
        """
        result = response_metadata_postprocess_hook(make_result(), None)
        response = result["paths"]["/fake/bodyless-204"]["delete"]["responses"]["204"]
        assert "content" not in response
        assert response == {"description": ""}

    def test_200_with_body_gets_metadata(self):
        """
        regular responses still get the global metadata
        """
        result = response_metadata_postprocess_hook(make_result(), None)
        response = result["paths"]["/fake/with-body"]["get"]["responses"]["200"]
        props = response["content"]["application/json"]["schema"]["properties"]
        assert METADATA_FIELDS <= set(props)

    def test_bodyless_200_gets_metadata_body(self):
        """
        only 204 is skipped, a 200 without content
        still gets the metadata body as before
        """
        result = response_metadata_postprocess_hook(make_result(), None)
        response = result["paths"]["/fake/bodyless-200"]["get"]["responses"]["200"]
        props = response["content"]["application/json"]["schema"]["properties"]
        assert METADATA_FIELDS <= set(props)
