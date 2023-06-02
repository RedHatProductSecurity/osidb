"""
Trackers exceptions
"""


class BTSException(Exception):
    """base exception class for BTS specific exceptions"""


class NoPriorityAvailableError(BTSException):
    """exception class for missing correct priority corresponding to FlawImpact"""


class UnsupportedTrackerError(BTSException):
    """
    exception class for the cases of the unsupported tracker filing
    which might be historical flaws or some deprecated workflows
    """
