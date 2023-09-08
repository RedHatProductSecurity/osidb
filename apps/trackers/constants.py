"""
common tracker constants
"""
from osidb.helpers import get_env

TRACKERS_API_VERSION = "v1"

# switch to enable or disable the Jira tracker sync
# - the one controlling the Bugzilla sync is defined in the BBSync app
SYNC_TO_JIRA = get_env("TRACKERS_SYNC_TO_JIRA", default="False", is_bool=True)

# tracker summary constants
MAX_SUMMARY_LENGTH = 255
MULTIPLE_DESCRIPTIONS_SUBSTITUTION = "various flaws"

# tracker description constants
KERNEL_PACKAGES = {"kernel", "realtime-kernel", "kernel-rt", "kernel-alt"}
VIRTUALIZATION_PACKAGES = {"xen", "kvm", "kernel-xen"}
