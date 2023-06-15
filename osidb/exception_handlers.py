from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.response import Response
from rest_framework.serializers import as_serializer_error
from rest_framework.views import exception_handler as drf_exception_handler


def exception_handler(exc, context):
    if http_code := getattr(type(exc), "http_code", False):
        # serialize custom exceptions when raised as part of the
        # request-response lifecycle by using an `http_code` class variable
        # as an interface
        response_data = {
            "detail": str(exc),
        }
        return Response(response_data, status=http_code)
    if isinstance(exc, DjangoValidationError):
        exc = DRFValidationError(as_serializer_error(exc))
    return drf_exception_handler(exc, context)
