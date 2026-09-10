from pydantic_settings import BaseSettings, SettingsConfigDict


class RegulatoryReportingSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="REGULATORY_REPORTING_")

    notifications_enabled: bool = False
    enabled: bool = False
    upstream_notifications_sender: str = ""


regulatory_reporting_settings = RegulatoryReportingSettings()
