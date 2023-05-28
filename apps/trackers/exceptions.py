"""
Trackers exceptions
"""


class BTSException(Exception):
    """base exception class for BTS specific exceptions"""


class NoPriorityAvailableError(BTSException):
    """exception class for missing correct priority corresponding to FlawImpact"""
