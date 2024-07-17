"""
Jiraffe exceptions
"""


class JiraffeException(Exception):
    """
    base exception class for Jiraffe specific exceptions
    """


class JiraTrackerCollectorConcurrentEditAvoided(JiraffeException):
    """
    detected a concurrent edit of the tracker model in DB, or of the related flaw
    """


class NonRecoverableJiraffeException(JiraffeException):
    """
    permanent exceptions consistent between runs
    may be malformed data or permission issues
    """


class MetadataCollectorInsufficientDataJiraffeException(JiraffeException):
    """
    Unable to download jira project metadata. Either unable to download any,
    or more than 20%, indicating breakage rather than slight administrative
    changes and transient errors. Using such data would make it impossible
    to work with Trackers.
    """
