import pytest
from rest_framework.exceptions import AuthenticationFailed

from ..backend import get_user_info

pytestmark = pytest.mark.unit


class TestCleanUsername:
    def test_normal_user(self, backend, normal_user):
        assert backend.clean_username(normal_user) == "foo"

    def test_normal_user_ipa(self, backend, normal_user_ipa):
        assert backend.clean_username(normal_user_ipa) == "foo"

    def test_host_user(self, backend, host_user):
        assert backend.clean_username(host_user) == "host/myservice.redhat.com"

    def test_hardcoded_user(self, monkeypatch, backend, hardcoded_user):
        import os

        def mock_getenv(env_var, default=""):
            if env_var == "KRB5_TO_LDAP_MAP":
                return '{"%s": "sdengine"}' % hardcoded_user
            return default

        monkeypatch.setattr(os, "getenv", mock_getenv)

        assert backend.clean_username(hardcoded_user) == "sdengine"


class TestLDAPCommunication:
    def test_user_info_valid_user(self, valid_user_username):
        user_info = get_user_info(valid_user_username)
        dn, attrs = user_info
        assert dn == f"cn={valid_user_username},ou=users,dc=redhat,dc=com"
        assert attrs["sn"][0].decode() == "Perlis"

    def test_user_info_valid_service(self, valid_service_username):
        user_info = get_user_info(valid_service_username)
        dn, attrs = user_info
        assert dn == f"cn={valid_service_username},ou=serviceaccounts,dc=redhat,dc=com"
        assert attrs["sn"][0].decode() == "Faker"

    def test_user_info_invalid_service(self, invalid_service_username):
        with pytest.raises(AuthenticationFailed) as e:
            get_user_info(invalid_service_username)
        msg = "Could not find matching LDAP account for Kerberos principal"
        assert msg == str(e.value)
