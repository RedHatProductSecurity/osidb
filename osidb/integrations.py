import logging
from pathlib import Path
from typing import Optional

import hvac
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from osidb.helpers import get_execution_env

_logger = logging.getLogger(__name__)


class IntegrationSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OSIDB_")

    vault_addr: str = Field(default="")
    role_id: str = Field(default="")
    secret_id: str = Field(default="")
    integrations_base_path: str = Field(default="/osidb-integrations")

    def is_vault_enabled(self) -> bool:
        """
        Determine if Vault should be enabled based on credentials.

        Vault is enabled only when ALL THREE credentials are provided:
        OSIDB_VAULT_ADDR, OSIDB_ROLE_ID, OSIDB_SECRET_ID
        """
        return bool(self.vault_addr and self.role_id and self.secret_id)


class IntegrationRepository:
    BASE_MOUNTPOINT = "apps"

    def __init__(self, settings: IntegrationSettings):
        self.settings = settings
        self.base_path = Path(settings.integrations_base_path) / Path(
            get_execution_env()
        )

        if not settings.is_vault_enabled():
            _logger.info(
                "Vault integration is disabled because required credentials are not provided"
            )
            self.client = None
            return

        # Credentials are guaranteed to be present by is_vault_enabled()
        self.client = hvac.Client(url=settings.vault_addr)
        try:
            self.client.auth.approle.login(
                role_id=settings.role_id, secret_id=settings.secret_id
            )
        except hvac.exceptions.VaultError as e:
            _logger.error("Vault AppRole authentication failed.", exc_info=e)

    def upsert_secret(self, subpath: Path, key: str, value: str) -> None:
        if self.client is None:
            _logger.debug(f"Vault is disabled, cannot write secret at {subpath}/{key}")
            return

        self.client.secrets.kv.v2.patch(
            path=str(self.base_path / subpath),
            secret={key: value},
            mount_point=self.BASE_MOUNTPOINT,
        )

    def read_secret(self, subpath: Path, key: str) -> Optional[str]:
        if self.client is None:
            _logger.debug(f"Vault is disabled, cannot read secret at {subpath}/{key}")
            return None

        r = self.client.secrets.kv.v2.read_secret_version(
            path=str(self.base_path / subpath),
            mount_point=self.BASE_MOUNTPOINT,
        )
        return r["data"]["data"].get(key)

    def upsert_jira_token(self, user: str, token: str) -> None:
        self.upsert_secret(Path("jira/token"), user, token)

    def upsert_jira_email(self, user: str, email: str) -> None:
        self.upsert_secret(Path("jira/email"), user, email)

    def upsert_bz_token(self, user: str, token: str) -> None:
        self.upsert_secret(Path("bugzilla"), user, token)

    def read_jira_token(self, user: str) -> Optional[str]:
        return self.read_secret(Path("jira/token"), user)

    def read_jira_email(self, user: str) -> Optional[str]:
        return self.read_secret(Path("jira/email"), user)

    def read_bz_token(self, user: str) -> Optional[str]:
        return self.read_secret(Path("bugzilla"), user)
