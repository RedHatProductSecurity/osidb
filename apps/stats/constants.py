"""
Stats constants
"""

from pydantic_settings import BaseSettings, SettingsConfigDict

STATS_API_VERSION: str = "v1beta"

MAX_BUCKET_BOUNDS: int = 12


class StatsAppSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OSIDB_STATS_")

    # SECURITY: Feature flag for the experimental stats aggregation API, kept
    # DISABLED by default. The endpoint runs under bypass_rls, so a flaw in the
    # impact/workflow grouping can leak embargoed data to unprivileged callers.
    #
    # TODO(OSIDB-5695): Do NOT re-enable this (do not flip the default, and do
    # not set OSIDB_STATS_ENABLED=1 in any deployed environment) until
    # OSIDB-5695 is RESOLVED and its outcome confirms the grouping is safe under
    # the new security guardrails. This is not a routine toggle — treat enabling
    # it as a security decision, not a config change.
    enabled: bool = False
