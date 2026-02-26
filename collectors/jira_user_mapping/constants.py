from pydantic_settings import BaseSettings, SettingsConfigDict


class JiraUserMappingCollectorSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="JIRA_USER_MAPPING_COLLECTOR_")

    enabled: bool = False
    url: str = ""


jira_user_mapping_collector_settings = JiraUserMappingCollectorSettings()
