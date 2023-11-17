"""
bzimport constants

these may eventually be refactored into config/settings

"""
from datetime import timedelta

from osidb.helpers import get_env

# API KEY used when making Bugzilla REST calls
BZ_API_KEY: str = get_env("BZIMPORT_BZ_API_KEY", default="")
BZ_URL: str = get_env("BZIMPORT_BZ_URL", default="https://bugzilla.redhat.com")
# Create new connection when its age is higher than specified value. Based on testing, idle
# connection is dropped after ~10 minutes.
BZ_MAX_CONNECTION_AGE = timedelta(minutes=1)

# enable importing of embargoed data - used by CI, local dev and test envs which have no need to retrieve embargoed flaws
BZ_ENABLE_IMPORT_EMBARGOED = get_env(
    "BZIMPORT_ENABLE_IMPORT_EMBARGOED", default="True", is_bool=True
)
# number of threads collecting in parallel
PARALLEL_THREADS = get_env("BZIMPORT_PARALLEL_THREADS", default="8", is_int=True)

# Bugzilla product for analysis tasks
ANALYSIS_TASK_PRODUCT = "Security Response"

# Bugzilla datetime format strings
BZ_DT_FMT = "%Y-%m-%dT%H:%M:%S%z"
BZ_DT_FMT_HISTORY = "%Y-%m-%dT%H:%M:%SZ"

FLAW_PLACEHOLDER_KEYWORD = "Tracking"
