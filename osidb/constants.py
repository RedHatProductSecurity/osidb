"""
osidb constants

these may eventually be refactored into config/settings

"""

import re
from datetime import timedelta, timezone

from .helpers import get_env

OSIDB_API_VERSION: str = "v1"

# include meta_attr column on all queries (useful for debugging)
OSIDB_VIEW_META_ATTR = False

TZ_OFFSET = 0  # GMT
TZINFO = timezone(timedelta(hours=TZ_OFFSET))

ENABLE_EMBARGO_PROCESS: bool = get_env(
    "OSIDB_EMBARGO_PROCESS", default="False", is_bool=True
)


# PyPI URL -- all dependent packages are installed from this package index
# used by osidb manifest endpoint to parse pypi urls
PYPI_URL = "https://pypi.org/project/"
URL_REGEX = re.compile(r"https?://[-a-zA-Z0-9@:%_\\+.~#!?&/=;]*[-a-zA-Z0-9@%_~#?&/]")
