"""
product definitions collector constants
"""

from osidb.helpers import get_env

PRODUCT_DEFINITIONS_REPO_URL = get_env("PRODUCT_DEF_URL", "")

PRODUCT_DEFINITIONS_REPO_BRANCH = get_env("PRODUCT_DEF_BRANCH", "master")

# Nested properties which should be remaped to normal properties
PROPERTIES_MAP = {
    "ps_modules": {
        "bts": {
            "name": "bts_name",
            "key": "bts_key",
            "groups": "bts_groups",
        },
        "lifecycle": {
            "supported_from": "supported_from_dt",
            "supported_until": "supported_until_dt",
        },
        "components": {
            "default": "default_component",
            "override": "component_overrides",
        },
    }
}

# List of relationship types between PS Update Stream and PS Module
PS_UPDATE_STREAM_RELATIONSHIP_TYPE = (
    "ps_update_streams",
    "active_ps_update_streams",
    "default_ps_update_streams",
    "eus_ps_update_streams",
    "aus_ps_update_streams",
    "unacked_ps_update_stream",
)
