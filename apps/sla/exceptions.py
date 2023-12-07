"""
SLA exceptions
"""


class SLAException(Exception):
    """
    base exception class for SLA specific exceptions
    """


class SLADefinitionError(SLAException):
    """
    exception class for SLA definition errors
    """


class SLAExecutionError(SLAException):
    """
    exception class for SLA execution errors
    """
