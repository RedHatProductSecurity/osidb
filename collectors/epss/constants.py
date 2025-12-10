from pydantic_settings import BaseSettings, SettingsConfigDict


class EPSSCollectorSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="EPSS_COLLECTOR_")

    enabled: bool = False


epss_collector_settings = EPSSCollectorSettings()
