import logging

from bugzilla.exceptions import BugzillaError
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.db.utils import OperationalError
from jira.exceptions import JIRAError
from rest_framework import status
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.response import Response
from rest_framework.serializers import as_serializer_error
from rest_framework.views import exception_handler as drf_exception_handler

logger = logging.getLogger(__name__)


def exception_handler(exc, context):
    if http_code := getattr(type(exc), "http_code", False):
        transaction.set_rollback(True)
        # serialize custom exceptions when raised as part of the
        # request-response lifecycle by using an `http_code` class variable
        # as an interface
        logger.exception(exc)
        response_data = {
            "detail": str(exc),
        }
        return Response(response_data, status=http_code)

    if isinstance(exc, BugzillaError):
        transaction.set_rollback(True)
        logger.exception(exc)
        data = {"detail": str(exc)}
        return Response(data, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

    if isinstance(exc, JIRAError):
        transaction.set_rollback(True)
        logger.exception(exc)
        data = {"detail": exc.text}
        return Response(data, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

    if isinstance(exc, OperationalError):
        transaction.set_rollback(True)
        logger.exception(exc)
        details = str(exc)
        if "deadlock" in details:
            data = {
                "detail": "[OperationalError] Concurrent access to the same model by you and someone else. For example, two clients editing the same Flaw. Exception details: "
                + details
            }
            return Response(data, status=status.HTTP_409_CONFLICT)

    if isinstance(exc, DjangoValidationError):
        exc = DRFValidationError(as_serializer_error(exc))

    return drf_exception_handler(exc, context)
