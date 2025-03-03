"""
    osidb middleware is responsible for injecting ldap user acls into all sql calls.
    For a user to access rows in a table it must have the correct acl.

"""

import logging

import pghistory
from django.conf import settings
from django.core.handlers.wsgi import WSGIRequest

from osidb.core import set_user_acls

_logger = logging.getLogger(__name__)


class PgCommon:
    """Set osidb.acl environment variable on all db calls

    osidb.acl is used with row-level security to control access to data
    It is a v5 UUID generated from a constant prefix plus an LDAP group name
    It is an identifier, not an actual list of users who can read / write
    Only records with a matching UUID in acl_read or acl_write can be read / written to
    LDAP group for local development is "data-prodsec"
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # by default set ACLs to public read if unauthenticated
        set_user_acls(settings.PUBLIC_READ_GROUPS)
        if request.user.is_authenticated:
            _logger.info(f"ACLs set from middleware for user {request.user.username}")
            set_user_acls(request.user.groups.all())
        return self.get_response(request)


def get_userstr(user):
    userstr = str(user)
    if getattr(user, "is_authenticated", False):
        if getattr(user, "email", False):
            userstr = user.email
        elif getattr(user, "username", False):
            userstr = user.username
    return userstr


class WSGIRequestWithHook(WSGIRequest):
    """
    Updates pghistory context when the request.user attribute is updated in order
    for context to be set before DB User-model lookup happens. User is added to the request
    by Django in middleware, but added to the request object in the view layer by
    django-rest-framework.
    """

    def __setattr__(self, attr, value):
        if attr == "user":
            pghistory.context(user=get_userstr(value))
        return super().__setattr__(attr, value)


class OsidbHistoryMiddleware:
    """
    Provides pghistory context with user email or name for use in FlawAudit model
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request or not hasattr(request, "user"):
            return self.get_response(request)

        with pghistory.context(user=get_userstr(request.user), path=request.path):
            if isinstance(request, WSGIRequest):
                request.__class__ = WSGIRequestWithHook
            return self.get_response(request)
