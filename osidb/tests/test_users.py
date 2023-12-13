import pytest
from bugzilla import Bugzilla
from django.contrib.auth.models import User
from jira import JIRA

from osidb.helpers import get_env

pytestmark = pytest.mark.unit


class TestUsers:
    @pytest.mark.enable_signals
    @pytest.mark.vcr
    def test_profile_creation_no_account(self, test_user_dict_no_account):
        new_user = User.objects.create(**test_user_dict_no_account)

        assert new_user.profile
        assert not new_user.profile.bz_user_id
        assert not new_user.profile.jira_user_id

    @pytest.mark.enable_signals
    @pytest.mark.vcr
    def test_profile_creation(self, test_user_dict):
        new_user = User.objects.create(**test_user_dict)

        assert new_user.profile
        assert new_user.profile.bz_user_id == "atorresj@redhat.com"
        assert new_user.profile.jira_user_id == "atorresj@redhat.com"
        # test that profile serialization works
        assert str(new_user.profile) == "foo"

        # verify that the user info can be fetched from bugzilla / jira
        bz_token = get_env("BZIMPORT_BZ_API_KEY")
        bz_url = get_env("BZIMPORT_BZ_URL", "https://bugzilla.redhat.com")
        jira_token = get_env("JIRA_AUTH_TOKEN")
        jira_url = get_env("JIRA_URL", "https://issues.redhat.com")
        bz_api = Bugzilla(bz_url, api_key=bz_token, force_rest=True)
        jira_api = JIRA(
            options={
                "server": jira_url,
                # avoid auto-updating the lib
                "check_update": False,
            },
            token_auth=jira_token,
            get_server_info=False,
        )

        assert bz_api.getuser(new_user.profile.bz_user_id)
        assert jira_api.user(new_user.profile.jira_user_id)
