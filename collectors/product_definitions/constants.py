"""
product definitions collector constants
"""

PRODUCT_DEFINITIONS_REPO_URL = (
    "https://git.prodsec.redhat.com/prodsec/product-definitions"
)
PRODUCT_DEFINITIONS_REPO_BRANCH = "master"

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
            "override": "components_override",
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
)
