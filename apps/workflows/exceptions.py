"""
Workflows exceptions
"""


class WorkflowsException(Exception):
    """base exception class for Workflows specific exceptions"""


class APIError(WorkflowsException):
    """exception class for API errors"""


class MissingStateException(WorkflowsException):
    """exception for handling a non-registered state"""


class WorkflowDefinitionError(WorkflowsException):
    """exception class for workflow definitions errors"""
