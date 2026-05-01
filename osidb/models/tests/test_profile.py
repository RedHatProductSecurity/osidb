from unittest.mock import patch

from django.contrib.auth.models import User

from osidb.models import Profile


class TestKerberosToCloudId:
    def test_returns_cached_cloud_id(self):
        """
        test case where Profile already has atlassian_cloud_id
        """
        user = User.objects.create(username="testuser")
        Profile.objects.create(user=user, atlassian_cloud_id="cached-cloud-id")

        result = Profile.kerberos_to_cloud_id("testuser")

        assert result == "cached-cloud-id"

    def test_fetches_and_caches_cloud_id_when_empty(self):
        """
        test case where Profile exists with empty atlassian_cloud_id
        and fetches from Jira API
        """
        user = User.objects.create(username="testuser2")
        Profile.objects.create(user=user, atlassian_cloud_id="")

        with patch("osidb.models.profile.get_jira_cloud_id") as mock_get:
            mock_get.return_value = "fetched-cloud-id"
            result = Profile.kerberos_to_cloud_id("testuser2")

        assert result == "fetched-cloud-id"
        assert (
            Profile.objects.get(user__username="testuser2").atlassian_cloud_id
            == "fetched-cloud-id"
        )
        mock_get.assert_called_once_with("testuser2")

    def test_creates_profile_when_missing(self):
        """creates user and profile if not exist"""

        with patch("osidb.models.profile.get_jira_cloud_id") as mock_get:
            mock_get.return_value = "new-cloud-id"
            result = Profile.kerberos_to_cloud_id("newuser")

        assert result == "new-cloud-id"
        assert Profile.objects.filter(user__username="newuser").exists()
