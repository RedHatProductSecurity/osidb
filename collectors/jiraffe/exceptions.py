"""
Jiraffe exceptions
"""


class JiraffeException(Exception):
    """
    base exception class for Jiraffe specific exceptions
    """


class NonRecoverableJiraffeException(JiraffeException):
    """
    permanent exceptions consistent between runs
    may be malformed data or permission issues
    """
