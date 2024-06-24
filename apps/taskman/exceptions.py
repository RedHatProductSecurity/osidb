"""
Taskman exceptions
"""


class TaskmanException(Exception):
    """base exception class for Taskman specific exceptions"""


class MissingJiraTokenException(TaskmanException):
    """exception for performing user action without providing token"""


class TaskWritePermissionsException(TaskmanException):
    """exception for performing task creation/update without permissions in the Jira project"""


class JiraTaskErrorException(TaskmanException):
    """exception for getting an error from Jira"""
