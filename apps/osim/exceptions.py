"""
OSIM exceptions
"""


class OSIMException(Exception):
    """base exception class for OSIM specific exceptions"""


class APIError(OSIMException):
    """exception class for API errors"""


class WorkflowDefinitionError(OSIMException):
    """exception class for workflow definitions errors"""
