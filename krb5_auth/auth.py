import socket

import kerberos
from django.conf import settings
from django.contrib.auth import authenticate
from drf_spectacular.extensions import OpenApiAuthenticationExtension
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed


class KerberosAuthentication(authentication.BaseAuthentication):
    """
    Authentication plugin that performs Kerberos authentication using the SPNEGO protocol
    """

    def authenticate_header(self, request):
        return "Negotiate"

    def authenticate(self, request):
        header = request.META.get("HTTP_AUTHORIZATION")
        if header is None:
            return

        auth_type, auth_token = header.split()
        if auth_type != "Negotiate":
            return

        HOSTNAME = "HTTP@{}".format(
            getattr(settings, "KRB5_HOSTNAME", socket.getfqdn()),
        )

        krb_context = None

        try:
            rc, krb_context = kerberos.authGSSServerInit(HOSTNAME)
            if rc != kerberos.AUTH_GSS_COMPLETE:
                # TODO: log error
                raise AuthenticationFailed

            rc = kerberos.authGSSServerStep(krb_context, auth_token)
            if rc == kerberos.AUTH_GSS_COMPLETE:
                username = kerberos.authGSSServerUserName(krb_context)
                token = kerberos.authGSSServerResponse(krb_context)
            else:
                # TODO: log error
                raise AuthenticationFailed
        except kerberos.GSSError:
            # TODO: log error
            raise AuthenticationFailed
        finally:
            if krb_context is not None:
                kerberos.authGSSServerClean(krb_context)
        user = authenticate(request, krb_principal=username)
        return user, token


class KerberosAuthenticationScheme(OpenApiAuthenticationExtension):
    """OpenAPI scheme extension for custom auth class to be properly discovered"""

    target_class = KerberosAuthentication
    name = "KerberosAuthentication"

    def get_security_definition(self, auto_schema):
        return {
            "type": "http",
            "scheme": "negotiate",
            "in": "header",
        }
