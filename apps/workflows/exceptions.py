"""
Workflows exceptions
"""


class WorkflowsException(Exception):
    """base exception class for Workflows specific exceptions"""


class APIError(WorkflowsException):
    """exception class for API errors"""


class WorkflowDefinitionError(WorkflowsException):
    """exception class for workflow definitions errors"""
