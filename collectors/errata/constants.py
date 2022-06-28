"""
Errata Tool collector constants
"""

from ssl import SSLError
from xmlrpc.client import ProtocolError

from requests.exceptions import RequestException

# Celery task constants
PAGE_SIZE = 100
RETRYABLE_ERRORS = (ProtocolError, RequestException, SSLError, TimeoutError)
