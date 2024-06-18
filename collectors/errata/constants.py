"""
Errata Tool collector constants
"""

from ssl import SSLError
from xmlrpc.client import ProtocolError

from requests.exceptions import RequestException

from osidb.helpers import get_env

# Celery task constants
PAGE_SIZE = 100
RETRYABLE_ERRORS = (ProtocolError, RequestException, SSLError, TimeoutError)

ERRATA_TOOL_SERVER = get_env("ET_URL")
ERRATA_TOOL_XMLRPC_BASE_URL = f"{ERRATA_TOOL_SERVER}/errata/errata_service"

# Switch to turn the collector on/off
ERRATA_COLLECTOR_ENABLED = get_env(
    "ERRATA_COLLECTOR_ENABLED", default="True", is_bool=True
)
