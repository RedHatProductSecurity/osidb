import pytest

from krb5_auth.backend import LDAPRemoteUser


@pytest.fixture
def normal_user():
    return "foo@REDHAT.COM"


@pytest.fixture
def normal_user_ipa():
    return "foo@IPA.REDHAT.COM"


@pytest.fixture
def host_user():
    return "host/myservice.redhat.com@REDHAT.COM"


@pytest.fixture
def hardcoded_user():
    return "host/sdengine-stage.prodsec.redhat.com@REDHAT.COM"


@pytest.fixture
def backend():
    return LDAPRemoteUser()


@pytest.fixture
def valid_user_username():
    return "atorresj"


@pytest.fixture
def valid_service_username():
    return "testservice"


@pytest.fixture
def invalid_service_username():
    return "foo"
