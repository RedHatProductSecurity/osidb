"""
SLA exceptions
"""


class SLAException(Exception):
    """
    base exception class for SLA specific exceptions
    """


class SLAExecutionError(SLAException):
    """
    exception class for SLA execution errors
    """
