from pathlib import Path

import pytest

from osidb.helpers import get_execution_env
from osidb.integrations import IntegrationRepository, IntegrationSettings

pytestmark = pytest.mark.unit


def test_integration_repo_upsert(fake_integration_repo, mock_hvac_client_instance):
    fake_integration_repo.upsert_secret(Path("foo"), "foo", "bar")

    mock_hvac_client_instance.secrets.kv.v2.patch.assert_called_once_with(
        path=f"/osidb-integrations/{get_execution_env()}/foo",
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
        path=f"/osidb-integrations/{get_execution_env()}/ham",
        mount_point="apps",
    )


def test_integration_repo_jira_token_upsert(
    fake_integration_repo, mock_hvac_client_instance
):
    fake_integration_repo.upsert_jira_token("atorresj", "my-token")

    mock_hvac_client_instance.secrets.kv.v2.patch.assert_called_once_with(
        path=f"/osidb-integrations/{get_execution_env()}/jira/token",
        secret={"atorresj": "my-token"},
        mount_point="apps",
    )


def test_integration_repo_jira_email_upsert(
    fake_integration_repo, mock_hvac_client_instance
):
    fake_integration_repo.upsert_jira_email("atorresj", "email@redhat.com")
    mock_hvac_client_instance.secrets.kv.v2.patch.assert_called_once_with(
        path=f"/osidb-integrations/{get_execution_env()}/jira/email",
        secret={"atorresj": "email@redhat.com"},
        mount_point="apps",
    )


def test_integration_repo_bz_upsert(fake_integration_repo, mock_hvac_client_instance):
    fake_integration_repo.upsert_bz_token("atorresj", "my-token")

    mock_hvac_client_instance.secrets.kv.v2.patch.assert_called_once_with(
        path=f"/osidb-integrations/{get_execution_env()}/bugzilla",
        secret={"atorresj": "my-token"},
        mount_point="apps",
    )


def test_integration_repo_read_jira_token(
    fake_integration_repo, mock_hvac_client_instance
):
    fake_integration_repo.read_jira_token("atorresj")
    mock_hvac_client_instance.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path=f"/osidb-integrations/{get_execution_env()}/jira/token",
        mount_point="apps",
    )


def test_integration_repo_read_jira_email(
    fake_integration_repo, mock_hvac_client_instance
):
    fake_integration_repo.read_jira_email("atorresj")
    mock_hvac_client_instance.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path=f"/osidb-integrations/{get_execution_env()}/jira/email",
        mount_point="apps",
    )


def test_integration_repo_read_bz_token(
    fake_integration_repo, mock_hvac_client_instance
):
    fake_integration_repo.read_bz_token("atorresj")
    mock_hvac_client_instance.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path=f"/osidb-integrations/{get_execution_env()}/bugzilla",
        mount_point="apps",
    )


def test_vault_disabled_when_vault_addr_missing():
    """Test that Vault is disabled when OSIDB_VAULT_ADDR is missing"""
    settings = IntegrationSettings(vault_addr="", role_id="test", secret_id="test")
    assert not settings.is_vault_enabled()


def test_vault_disabled_when_role_id_missing():
    """Test that Vault is disabled when OSIDB_ROLE_ID is missing"""
    settings = IntegrationSettings(
        vault_addr="http://vault:8200", role_id="", secret_id="test"
    )
    assert not settings.is_vault_enabled()


def test_vault_disabled_when_secret_id_missing():
    """Test that Vault is disabled when OSIDB_SECRET_ID is missing"""
    settings = IntegrationSettings(
        vault_addr="http://vault:8200", role_id="test", secret_id=""
    )
    assert not settings.is_vault_enabled()


def test_vault_disabled_when_all_credentials_missing(monkeypatch):
    """Test that Vault is disabled when all credentials are missing"""
    monkeypatch.delenv("OSIDB_VAULT_ADDR", raising=False)
    monkeypatch.delenv("OSIDB_ROLE_ID", raising=False)
    monkeypatch.delenv("OSIDB_SECRET_ID", raising=False)

    settings = IntegrationSettings()  # All credentials default to empty string
    assert not settings.is_vault_enabled()


def test_vault_enabled_when_all_credentials_provided(set_hvac_test_env_vars):
    """Test that Vault is enabled when all THREE credentials are provided"""
    settings = IntegrationSettings()
    assert settings.is_vault_enabled()


def test_vault_disabled_read_returns_none(monkeypatch):
    """Test that read operations return None when Vault is disabled"""
    monkeypatch.delenv("OSIDB_VAULT_ADDR", raising=False)
    monkeypatch.delenv("OSIDB_ROLE_ID", raising=False)
    monkeypatch.delenv("OSIDB_SECRET_ID", raising=False)

    settings = IntegrationSettings()  # All credentials empty
    repo = IntegrationRepository(settings)

    assert repo.read_secret(Path("test"), "key") is None
    assert repo.read_jira_token("testuser") is None
    assert repo.read_jira_email("testuser") is None
    assert repo.read_bz_token("testuser") is None


def test_vault_disabled_write_is_noop(monkeypatch):
    """Test that write operations are no-ops when Vault is disabled"""
    monkeypatch.delenv("OSIDB_VAULT_ADDR", raising=False)
    monkeypatch.delenv("OSIDB_ROLE_ID", raising=False)
    monkeypatch.delenv("OSIDB_SECRET_ID", raising=False)

    settings = IntegrationSettings()  # All credentials empty
    repo = IntegrationRepository(settings)

    # These should not raise exceptions, just no-op
    repo.upsert_secret(Path("test"), "key", "value")
    repo.upsert_jira_token("testuser", "token")
    repo.upsert_jira_email("testuser", "email@example.com")
    repo.upsert_bz_token("testuser", "token")

    assert repo.client is None


def test_vault_repository_init_with_missing_credentials(monkeypatch):
    """Test that IntegrationRepository gracefully handles missing credentials"""
    monkeypatch.delenv("OSIDB_VAULT_ADDR", raising=False)
    monkeypatch.delenv("OSIDB_ROLE_ID", raising=False)
    monkeypatch.delenv("OSIDB_SECRET_ID", raising=False)

    settings = IntegrationSettings(
        vault_addr="http://vault:8200"
    )  # Partial credentials
    repo = IntegrationRepository(settings)

    # Should have None client without raising
    assert repo.client is None
