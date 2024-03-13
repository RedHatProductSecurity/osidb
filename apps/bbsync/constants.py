"""
BBSync constants
"""
import os

from collectors.bzimport.constants import BZ_DT_FMT_HISTORY
from osidb.helpers import get_env

DATE_FMT = "%Y-%m-%d"
# these two time formats are the same
# thus spare us defining it again
DATETIME_FMT = BZ_DT_FMT_HISTORY

# RHSCL Bugzilla project key
RHSCL_BTS_KEY = "Red Hat Software Collections"

# JSON schema for SRT notes flaw metadata
SRTNOTES_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "./srtnotes-schema.json")

# switch to enable or disable BBSync
SYNC_TO_BZ = get_env("BBSYNC_SYNC_TO_BZ", default="False", is_bool=True)

# in SFM2 there are Bugzilla bot accounts and invalid users being filtered out from the CC lists
# however the list of the corresponding emails is being pulled from VDB by the old vdbqb library
# and we definitelly do not want such a dependence in OSIDB so I am adding the list statically
# here as the best we can do now and a motivation to leave Bugzilla as soon as possible
USER_BLACKLIST: list = get_env("BZ_USER_BLACKLIST", default="[]", is_json=True)
