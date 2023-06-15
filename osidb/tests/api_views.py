from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny

from osidb.exceptions import DataInconsistencyException


@api_view(["GET"])
@permission_classes((AllowAny,))
def my_view(_):
    raise DataInconsistencyException("This was a big failure")
