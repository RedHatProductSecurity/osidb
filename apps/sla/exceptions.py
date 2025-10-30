"""
SLA exceptions
"""


class TemporalPolicyException(Exception):
    """
    base exception class for TemporalPolicy specific exceptions
    """


class TemporalPolicyExecutionError(TemporalPolicyException):
    """
    exception class for TemporalPolicy execution errors
    """
