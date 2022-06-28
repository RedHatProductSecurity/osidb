"""
bzimport constants

these may eventually be refactored into config/settings

"""

from osidb.helpers import get_env

# API KEY used when making Bugzilla REST calls
BZ_API_KEY: str = get_env("BZIMPORT_BZ_API_KEY", default="")
BZ_URL: str = get_env("BZIMPORT_BZ_URL", default="https://bugzilla.redhat.com")

# enable importing of embargoed data - used by CI, local dev and test envs which have no need to retrieve embargoed flaws
BZ_ENABLE_IMPORT_EMBARGOED = get_env(
    "BZIMPORT_ENABLE_IMPORT_EMBARGOED", default="True", is_bool=True
)

ROOT_CA_PATH = get_env("ROOT_CA_PATH")

# nvd cvss url
NVD_CVSS_URL = "https://dashboard.prodsec.redhat.com/rest/api/latest/nvd_cvss"

# Bugzilla product for analysis tasks
ANALYSIS_TASK_PRODUCT = "Security Response"

# Bugzilla datetime format strings
BZ_DT_FMT = "%Y-%m-%dT%H:%M:%S%z"
BZ_DT_FMT_HISTORY = "%Y-%m-%dT%H:%M:%SZ"
