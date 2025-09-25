"""
Workflows exceptions
"""


class WorkflowsException(Exception):
    """base exception class for Workflows specific exceptions"""


class APIError(WorkflowsException):
    """exception class for API errors"""


class LastStateException(WorkflowsException):
    """exception for trying to promote further when in the last possible state"""


class InitialStateException(WorkflowsException):
    """exception for trying to revert further when in the first possible state"""


class MissingRequirementsException(WorkflowsException):
    """exception for trying to change state without requirements"""


class MissingStateException(WorkflowsException):
    """exception for handling a non-registered state"""


class MissingWorkflowException(WorkflowsException):
    """exception for handling a non-registered workflow"""


class WorkflowDefinitionError(WorkflowsException):
    """exception class for workflow definitions errors"""
