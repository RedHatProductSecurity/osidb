from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.serializers import as_serializer_error
from rest_framework.views import exception_handler as drf_exception_handler


def exception_handler(exc, context):
    # from https://stackoverflow.com/a/67185502
    if isinstance(exc, DjangoValidationError):
        exc = DRFValidationError(as_serializer_error(exc))
    return drf_exception_handler(exc, context)
