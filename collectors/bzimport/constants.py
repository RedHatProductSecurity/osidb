"""
bzimport constants

these may eventually be refactored into config/settings

"""

from osidb.helpers import get_env

# API KEY used when making Bugzilla REST calls
BZ_API_KEY: str = get_env("BZIMPORT_BZ_API_KEY")
BZ_URL: str = get_env("BZIMPORT_BZ_URL", default="https://bugzilla.redhat.com")

# enable importing of embargoed data - used by CI, local dev and test envs which have no need to retrieve embargoed flaws
BZ_ENABLE_IMPORT_EMBARGOED = get_env(
    "BZIMPORT_ENABLE_IMPORT_EMBARGOED", default="True", is_bool=True
)

# Bugzilla product for analysis tasks
ANALYSIS_TASK_PRODUCT = "Security Response"

# Bugzilla datetime format string
BZ_DT_FMT = "%Y-%m-%dT%H:%M:%S%z"

FLAW_PLACEHOLDER_KEYWORD = "Tracking"

# Maximum age of connection to Bugzilla in seconds, recommended value is 60
BZ_MAX_CONNECTION_AGE = get_env("BZ_MAX_CONNECTION_AGE")

# Switches to turn each collector on/off
FLAW_COLLECTOR_ENABLED = get_env("FLAW_COLLECTOR_ENABLED", default="True", is_bool=True)
BZ_TRACKER_COLLECTOR_ENABLED = get_env(
    "BZ_TRACKER_COLLECTOR_ENABLED", default="True", is_bool=True
)
BZ_METADATA_COLLECTOR_ENABLED = get_env(
    "BZ_METADATA_COLLECTOR_ENABLED", default="True", is_bool=True
)
