import logging
from pathlib import Path
from typing import Optional

import hvac
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from config import get_env

_logger = logging.getLogger(__name__)


class IntegrationSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OSIDB_")

    vault_addr: str = Field(default=...)
    role_id: str = Field(default=...)
    secret_id: str = Field(default=...)


class IntegrationRepository:
    BASE_PATH = Path("/osidb-integrations") / Path(get_env())
    BASE_MOUNTPOINT = "apps"

    def __init__(self, settings: IntegrationSettings):
        self.client = hvac.Client(url=settings.vault_addr)
        try:
            self.client.auth.approle.login(
                role_id=settings.role_id, secret_id=settings.secret_id
            )
        except hvac.exceptions.VaultError as e:
            _logger.error("Vault AppRole authentication failed.", exc_info=e)

    def upsert_secret(self, subpath: Path, key: str, value: str) -> None:
        self.client.secrets.kv.v2.patch(
            path=str(self.BASE_PATH / subpath),
            secret={key: value},
            mount_point=self.BASE_MOUNTPOINT,
        )

    def read_secret(self, subpath: Path, key: str) -> Optional[str]:
        r = self.client.secrets.kv.v2.read_secret_version(
            path=str(self.BASE_PATH / subpath),
            mount_point=self.BASE_MOUNTPOINT,
        )
        return r["data"]["data"].get(key)

    def upsert_jira_token(self, user: str, token: str) -> None:
        self.upsert_secret(Path("jira"), user, token)

    def upsert_bz_token(self, user: str, token: str) -> None:
        self.upsert_secret(Path("bugzilla"), user, token)

    def read_jira_token(self, user: str) -> Optional[str]:
        return self.read_secret(Path("jira"), user)

    def read_bz_token(self, user: str) -> Optional[str]:
        return self.read_secret(Path("bugzilla"), user)
