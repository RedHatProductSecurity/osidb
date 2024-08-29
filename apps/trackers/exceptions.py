"""
Trackers exceptions
"""


class BTSException(Exception):
    """base exception class for BTS specific exceptions"""


class ComponentUnavailableError(BTSException):
    """exception class for BTS not supporting the given component in the given project"""


class MissingEmbargoStatusError(BTSException):
    """
    Exception class for missing allowed value for Embargo Status field in the project.
    """


class MissingPriorityError(BTSException):
    """exception class for missing correct priority corresponding to Impact"""


class MissingSecurityLevelError(BTSException):
    """exception class for missing correct Security Level in the particular project"""


class MissingSeverityError(BTSException):
    """exception class for missing correct severity corresponding to Impact"""


class MissingSourceError(BTSException):
    """exception class for missing correct allowed source corresponding to FlawSource"""


class MissingSpecialHandlingError(BTSException):
    """exception class for missing values in the Special Handling multichoice field"""


class MissingTargetReleaseVersionError(BTSException):
    """
    Exception class for missing target release (or its fallback target version) value in the project.
    """


class MissingVulnerabilityIssueFieldError(BTSException):
    """
    exception class for missing field for the Vulnerability issuetype in the project
    """


class TrackerCreationError(BTSException):
    """
    exception class for the cases of unsuccessful tracker creation
    """


class UnsupportedTrackerError(BTSException):
    """
    exception class for the cases of the unsupported tracker filing
    which might be historical flaws or some deprecated workflows
    """
