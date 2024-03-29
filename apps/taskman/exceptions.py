"""
Taskman exceptions
"""


class TaskmanException(Exception):
    """base exception class for Taskman specific exceptions"""


class MissingJiraTokenException(TaskmanException):
    """exception for performing user action without providing token"""
