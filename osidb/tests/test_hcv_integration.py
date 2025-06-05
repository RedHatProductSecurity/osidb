from pathlib import Path

import pytest

from config import get_env

pytestmark = pytest.mark.unit


def test_integration_repo_upsert(fake_integration_repo, mock_hvac_client_instance):
    fake_integration_repo.upsert_secret(Path("foo"), "foo", "bar")

    mock_hvac_client_instance.secrets.kv.v2.patch.assert_called_once_with(
        path=f"/osidb-integrations/{get_env()}/foo",
        secret={"foo": "bar"},
        mount_point="apps",
    )


@pytest.mark.parametrize("ret_val,expected_out", [({"eggs": "ham"}, "ham"), ({}, None)])
def test_integration_repo_read(
    fake_integration_repo, mock_hvac_client_instance, ret_val, expected_out
):
    mock_hvac_client_instance.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": ret_val}
    }
    assert fake_integration_repo.read_secret(Path("ham"), "eggs") == expected_out
    mock_hvac_client_instance.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path=f"/osidb-integrations/{get_env()}/ham",
        mount_point="apps",
    )


def test_integration_repo_jira_upsert(fake_integration_repo, mock_hvac_client_instance):
    fake_integration_repo.upsert_jira_token("atorresj", "my-token")

    mock_hvac_client_instance.secrets.kv.v2.patch.assert_called_once_with(
        path=f"/osidb-integrations/{get_env()}/jira",
        secret={"atorresj": "my-token"},
        mount_point="apps",
    )


def test_integration_repo_bz_upsert(fake_integration_repo, mock_hvac_client_instance):
    fake_integration_repo.upsert_bz_token("atorresj", "my-token")

    mock_hvac_client_instance.secrets.kv.v2.patch.assert_called_once_with(
        path=f"/osidb-integrations/{get_env()}/bugzilla",
        secret={"atorresj": "my-token"},
        mount_point="apps",
    )


def test_integration_repo_read_jira_token(
    fake_integration_repo, mock_hvac_client_instance
):
    fake_integration_repo.read_jira_token("atorresj")
    mock_hvac_client_instance.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path=f"/osidb-integrations/{get_env()}/jira",
        mount_point="apps",
    )


def test_integration_repo_read_bz_token(
    fake_integration_repo, mock_hvac_client_instance
):
    fake_integration_repo.read_bz_token("atorresj")
    mock_hvac_client_instance.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path=f"/osidb-integrations/{get_env()}/bugzilla",
        mount_point="apps",
    )
