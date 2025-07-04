"""
common tracker constants
"""
from osidb.helpers import get_env

TRACKERS_API_VERSION = "v1"

# switch to enable or disable the Jira tracker sync
# - the one controlling the Bugzilla sync is defined in the BBSync app
SYNC_TO_JIRA = get_env("TRACKERS_SYNC_TO_JIRA", default="False", is_bool=True)

# tracker description constants
KERNEL_PACKAGES = {"kernel", "realtime-kernel", "kernel-rt", "kernel-alt"}
VIRTUALIZATION_PACKAGES = {"xen", "kvm", "kernel-xen"}

# link to essential Vuln Mgmt documentation
VULN_MGMT_INFO_URL = get_env("VULN_MGMT_INFO_URL", default=None)
