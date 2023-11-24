import os
import re

# Default request timeout value
REQUEST_TIMEOUT = 120  # seconds

FEEDS_FILE_NAME = "config.yml"
FEEDS_FILE = os.path.join(os.path.dirname(__file__), FEEDS_FILE_NAME)

CWE_RE_STR = re.compile(r"CWE-[1-9]\d*", flags=re.IGNORECASE)

PHRASE_TO_CWE_MAP = {
    "follow symlinks": "CWE-59",
    "follow links": "CWE-59",
    "xss": "CWE-79",
    "csp": "CWE-79",
    "does not sufficiently sanitize": "CWE-95",
    "does not sanitize": "CWE-95",
    "buffer overflow": "CWE-120",
    "segmentation fault": "CWE-120",
    "memory safety": "CWE-120",
    "private browsing": "CWE-212",
    "timing attack": "CWE-385",
    "after-free": "CWE-416",
    "after free": "CWE-416",
    "freed while it is still in use": "CWE-416",
    "use-after-free": "CWE-416",
    "url spoofing": "CWE-451",
    "file name spoofing": "CWE-451",
    "no warning": "CWE-451",
    "load local content": "CWE-552",
    "local file": "CWE-552",
    "out-of-bounds write": "CWE-787",
    "csrf": "CWE-829",
    "cross-origin": "CWE-829",
    "same-origin": "CWE-829",
    "permission checks bypass": "CWE-829",
    "permission check bypass": "CWE-829",
    "protections bypass": "CWE-829",
    "protection bypass": "CWE-829",
}
