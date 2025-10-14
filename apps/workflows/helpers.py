"""
various helper functions
"""

from .exceptions import APIError


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
