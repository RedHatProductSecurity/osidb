from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from osidb.auth import OsidbTokenAuthentication

from .auth import KerberosAuthentication


@extend_schema_view(
    get=extend_schema(
        responses={
            200: {
                "type": "object",
                "properties": {
                    "refresh": {"type": "string"},
                    "access": {"type": "string"},
                },
            }
        }
    )
)
@api_view()
@authentication_classes((KerberosAuthentication,))
@permission_classes((IsAuthenticated,))
def krb5_obtain_token_pair_view(request):
    """
    Takes a kerberos ticket and returns an access and refresh JWT pair.
    """
    refresh_token = RefreshToken.for_user(request.user)
    data = {
        "refresh": str(refresh_token),
        "access": str(refresh_token.access_token),
    }
    headers = {
        "WWW-Authenticate": f"Negotiate {request.auth}",
    }
    return Response(data, status=status.HTTP_200_OK, headers=headers)


# NOTE: Purpose of this custom class is for Kerberos authenticated
# GET method to be able to appear in the OpenAPI schema.
# We use Kerberos only for stage/production instances and the
# local instances are using the POST method with credentials.
# However this way only the POST method shows in the OpenAPI schema
# which is stored in the repository. Using this custom class we
# are able to show Kerberos auth GET method as well. Of course
# since Kerberos auth is not possible on local instance, endpoint
# will return 405 METHOD NOT ALLOWED code with the warning message
# stating that the Kerberos is not enabled and you should use the
# POST method with the credentials instead.
class OsidbTokenObtainPairView(TokenObtainPairView):
    @extend_schema(
        responses={
            200: {
                "type": "object",
                "properties": {
                    "refresh": {"type": "string"},
                    "access": {"type": "string"},
                },
            }
        },
        description=(
            "Takes a kerberos ticket and returns an access and refresh JWT pair."
        ),
        auth=[{"KerberosAuthentication": []}],
    )
    def get(self, request, *args, **kwargs):
        return Response(
            data={
                "detail": (
                    "Kerberos authentication is not enabled. "
                    "Use POST method with credentials instead."
                )
            },
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
        )
