import json
import os

import ldap
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group
from rest_framework.exceptions import AuthenticationFailed


# Global TODO: Move hardcoded data into settings
def get_ldap_groups(user_dn):
    # TODO: move into class and do connection only once on init
    conn = ldap.initialize(settings.AUTH_LDAP_SERVER_URI, bytes_mode=False)
    conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
    conn.simple_bind_s("", "")
    group_base = "ou=adhoc,ou=managedgroups,dc=redhat,dc=com"
    filter = f"(&(objectClass=groupOfUniqueNames)(uniqueMember={user_dn}))"
    attrlist = ["cn"]
    groups = conn.search_s(group_base, ldap.SCOPE_SUBTREE, filter, attrlist)
    return {group[1]["cn"][0].decode() for group in groups}


def get_user_info(username):
    conn = ldap.initialize(settings.AUTH_LDAP_SERVER_URI, bytes_mode=False)
    conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
    conn.simple_bind_s("", "")
    base = "ou=%s,dc=redhat,dc=com"
    attrlist = ["givenName", "sn", "mail"]
    user = conn.search_s(
        base % "users", ldap.SCOPE_SUBTREE, f"(uid={username})", attrlist
    )
    if not user:
        user = conn.search_s(
            base % "serviceaccounts", ldap.SCOPE_SUBTREE, f"(uid={username})", attrlist
        )
        if not user:
            # TODO: log mismatched username
            raise AuthenticationFailed(
                "Could not find matching LDAP account for Kerberos principal"
            )
    return user[0]


class LDAPRemoteUser(ModelBackend):
    # This emulates django's RemoteUserBackend but with some modifications
    # to the authenticate method in order to always synchronize DB users
    # with the remote system (LDAP)
    # TODO: in Django 4.1, the override to authenticate is not necessary
    # as configure_user has been changed to do both initial configuration
    # and continuous synchronization:
    # https://github.com/django/django/pull/15492

    def authenticate(self, request, krb_principal):
        """
        The username passed as ``krb_principal`` is considered trusted.

        This method returns the ``User`` object linked to the given username,
        either by fetching it from the database if it exists or by creating
        a new one. In both cases, the ``User`` object is synchronized with
        the configured LDAP server for authorization purposes.
        """
        if not krb_principal:
            return
        User = get_user_model()
        username = self.clean_username(krb_principal)

        user, created = User._default_manager.get_or_create(
            **{User.USERNAME_FIELD: username},
        )
        if created:
            user = self.configure_user(request, user)
        user = self.sync_user(request, user)
        return user if self.user_can_authenticate(user) else None

    def configure_user(self, request, user):
        """
        Configure a user after creation and return the updated user.
        """
        user.set_unusable_password()
        return user

    def sync_user(self, request, user):
        """
        Synchronize the user with the external system and return the updated user.
        """
        username = user.get_username()
        dn, attrs = get_user_info(username)
        groups = get_ldap_groups(dn)
        # Note: we simply create Groups without handling Django-style permissions
        # since we don't really use them -- we use PostgreSQL RLS
        group_objs = [Group.objects.get_or_create(name=group)[0] for group in groups]
        user.first_name = attrs["givenName"][0].decode()
        user.last_name = attrs["sn"][0].decode()
        user.email = attrs["mail"][0].decode()
        user.is_active = bool(set(settings.PUBLIC_READ_GROUPS) & groups)
        user.is_staff = settings.SERVICE_MANAGE_GROUP in groups
        user.is_superuser = settings.SERVICE_MANAGE_GROUP in groups
        # Note: unlike django-auth-ldap, we do create users for anyone who
        # attempts to connect to the service, however if they do not have the
        # required group for is_active (e.g. red-hat-product-security-osidb)
        # the user will be denied access when performing the user_can_authenticate
        # check
        user.save()
        user.groups.set(group_objs)
        return user

    def clean_username(self, username):
        """
        Perform any cleaning on the "username" prior to using it to get or
        create the ``User`` object. Return the cleaned username.
        """
        KRB5_TO_LDAP_MAP = json.loads(os.getenv("KRB5_TO_LDAP_MAP", "{}"))
        # username is a kerberos principal, extract the relevant part
        if username in KRB5_TO_LDAP_MAP:
            return KRB5_TO_LDAP_MAP[username]
        return username.rsplit("@", 1)[0]
