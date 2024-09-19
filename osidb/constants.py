"""
osidb constants

these may eventually be refactored into config/settings

"""

import re
from datetime import timedelta, timezone
from decimal import Decimal

OSIDB_API_VERSION: str = "v1"

# include meta_attr column on all queries (useful for debugging)
OSIDB_VIEW_META_ATTR = False

TZ_OFFSET = 0  # GMT
TZINFO = timezone(timedelta(hours=TZ_OFFSET))

# the default datetime format
DATETIME_FMT = "%Y-%m-%dT%H:%M:%SZ"


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


# This is a BZ ID used for marking a certain point in time of flaw analysis in BZ
# any issues before and including this one belong to the "old way" of having
# update streams instead of ps_modules for affects, any issues after this one
# belong to the "new way" in which ps_modules are more heavily enforced
BZ_ID_SENTINEL = 1489716

# Lists of components from RHSCL without collection
COMPONENTS_WITHOUT_COLLECTION = ["source-to-image", "scl-utils"]

# List of ps_product that are classified as services
SERVICES_PRODUCTS = [
    "ansible-services",
    "cloud-redhat-com",
    "hosted-openshift",
    "insights",
    "managed-application-services",
    "other-services",
    "openshift-hosted",
    "hostedservices",
]
