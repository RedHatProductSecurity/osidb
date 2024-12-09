import pytest
from django.contrib.auth.models import User

pytestmark = pytest.mark.unit


class TestUsers:
    @pytest.mark.enable_signals
    def test_profile_creation_no_account(self, test_user_dict_no_account):
        new_user = User.objects.create(**test_user_dict_no_account)

        assert new_user.profile
