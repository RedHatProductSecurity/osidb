"""
OSIM exceptions
"""


class OSIMException(Exception):
    """base exception class for OSIM specific exceptions"""


class APIError(OSIMException):
    """exception class for API errors"""


class LastStateException(OSIMException):
    """exception for trying to promote further when in the last possible state"""


class MissingRequirementsException(OSIMException):
    """exception for trying to change state without requirements"""


class MissingStateException(OSIMException):
    """exception for handling a non-registered state"""


class MissingWorkflowException(OSIMException):
    """exception for handling a non-registered workflow"""


class WorkflowDefinitionError(OSIMException):
    """exception class for workflow definitions errors"""
