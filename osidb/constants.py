"""
osidb constants

these may eventually be refactored into config/settings

"""

import re
from datetime import timedelta, timezone
from decimal import Decimal

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

CVSS3_SEVERITY_SCALE = {
    "none": (Decimal("0.0"), Decimal("0.0")),
    "low": (Decimal("0.1"), Decimal("3.9")),
    "medium": (Decimal("4.0"), Decimal("6.9")),
    "high": (Decimal("7.0"), Decimal("8.9")),
    "critical": (Decimal("9.0"), Decimal("10.0")),
}
