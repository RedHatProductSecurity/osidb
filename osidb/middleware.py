"""
    osidb middleware is responsible for injecting ldap user acls into all sql calls.
    For a user to access rows in a table it must have the correct acl.

"""
import logging

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
        if request.user.is_authenticated:
            _logger.info(f"ACLs set from middleware for user {request.user.username}")
            set_user_acls(request.user.groups.all())
        return self.get_response(request)
