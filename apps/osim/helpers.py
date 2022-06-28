"""
various helper functions
"""

import re

from django.http import Http404

from osidb.validators import CVE_RE_STR

from .exceptions import APIError


def get_flaw_or_404(pk):
    """get flaw instance or raise HTTP 404 error"""
    # import here to prevent cycle
    from osidb.models import Flaw

    try:
        if re.match(CVE_RE_STR, pk):
            return Flaw.objects.get(cve_id=pk)
        return Flaw.objects.get(pk=pk)
    except Flaw.DoesNotExist as e:
        raise Http404 from e


# singleton wrapper based on the following docs
# https://pypi.org/project/singleton-decorator/
#   simple but has its disadvantage described
#   there and if it was a problem replace it
def singleton(cls):
    """singleton class decorator"""
    instances = {}

    def wrapper(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return wrapper


def str2bool(val, param):
    """process textual form of boolean to native boolean"""

    if val in ["true", "True", "1"]:
        return True

    if val in ["false", "False", "0"]:
        return False

    raise APIError(f'Unexpected boolean value "{val}" for query parameter "{param}"')
