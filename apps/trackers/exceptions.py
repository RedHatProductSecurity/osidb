"""
Trackers exceptions
"""


class BTSException(Exception):
    """base exception class for BTS specific exceptions"""


class ComponentUnavailableError(BTSException):
    """exception class for BTS not supporting the given component in the given project"""


class NoPriorityAvailableError(BTSException):
    """exception class for missing correct priority corresponding to Impact"""


class NoSecurityLevelAvailableError(BTSException):
    """exception class for missing correct Security Level in the particular project"""


class NoTargetReleaseVersionAvailableError(BTSException):
    """
    Exception class for missing target release (or its fallback target version) value in the project.
    """


class TrackerCreationError(BTSException):
    """
    exception class for the cases of unsuccessful tracker creation
    """


class UnsupportedTrackerError(BTSException):
    """
    exception class for the cases of the unsupported tracker filing
    which might be historical flaws or some deprecated workflows
    """
