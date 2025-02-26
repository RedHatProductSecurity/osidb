import logging

from bugzilla.exceptions import BugzillaError, BugzillaHTTPError
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db.utils import OperationalError
from jira.exceptions import JIRAError
from rest_framework import status
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.response import Response
from rest_framework.serializers import as_serializer_error
from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework.views import set_rollback

from apps.taskman.exceptions import JiraTaskErrorException
from apps.trackers.exceptions import (
    ComponentUnavailableError,
    MissingJiraProjectMetadata,
    MissingSeverityError,
    MissingSourceError,
    MissingSpecialHandlingError,
    MissingTargetReleaseVersionError,
    MissingVulnerabilityIssueFieldError,
    TrackerCreationError,
)
from collectors.bzimport.exceptions import RecoverableBZImportException

logger = logging.getLogger(__name__)


def exception_handler(exc, context):
    if http_code := getattr(type(exc), "http_code", False):
        set_rollback()
        # serialize custom exceptions when raised as part of the
        # request-response lifecycle by using an `http_code` class variable
        # as an interface
        logger.exception(exc)
        response_data = {
            "detail": str(exc),
        }
        return Response(response_data, status=http_code)

    if isinstance(exc, (BugzillaError, BugzillaHTTPError)):
        set_rollback()
        logger.exception(exc)
        data = {"detail": str(exc)}
        return Response(data, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

    if isinstance(exc, JIRAError):
        set_rollback()
        logger.exception(exc)
        data = {"detail": parse_jira_error(exc)}
        return Response(data, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

    if isinstance(exc, OperationalError):
        set_rollback()
        logger.exception(exc)
        details = str(exc)
        if "deadlock" in details:
            data = {
                "detail": "[OperationalError] Concurrent access to the same model by you and someone else. For example, two clients editing the same Flaw. Exception details: "
                + details
            }
            return Response(data, status=status.HTTP_409_CONFLICT)

    KNOWN_EXCEPTIONS = (
        # Taskman
        JiraTaskErrorException,
        # Trackers
        ComponentUnavailableError,
        MissingJiraProjectMetadata,
        MissingSeverityError,
        MissingSourceError,
        MissingSpecialHandlingError,
        MissingTargetReleaseVersionError,
        MissingVulnerabilityIssueFieldError,
        TrackerCreationError,
        # BZImport
        RecoverableBZImportException,
    )

    if isinstance(exc, KNOWN_EXCEPTIONS):
        set_rollback()
        logger.exception(exc)
        data = {"detail": str(exc)}
        return Response(data, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

    if isinstance(exc, DjangoValidationError):
        exc = DRFValidationError(as_serializer_error(exc))

    return drf_exception_handler(exc, context)


def parse_jira_error(exc: JIRAError):
    if exc.text:
        return exc.text
    if getattr(exc, "response", None) is None:
        return "unknown Jira error"

    response = exc.response.json()
    return response.get(
        "errors", {"error": "unknown jira error", "status": exc.response.status_code}
    )
