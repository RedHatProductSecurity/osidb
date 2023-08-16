"""
Trackers exceptions
"""


class BTSException(Exception):
    """base exception class for BTS specific exceptions"""


class NoPriorityAvailableError(BTSException):
    """exception class for missing correct priority corresponding to Impact"""


class TrackerCreationError(BTSException):
    """
    exception class for the cases of unsuccessful tracker creation
    """


class UnsupportedTrackerError(BTSException):
    """
    exception class for the cases of the unsupported tracker filing
    which might be historical flaws or some deprecated workflows
    """
