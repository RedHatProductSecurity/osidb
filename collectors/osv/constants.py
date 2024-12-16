from osidb.helpers import get_env, get_env_date

# Switch to turn the collector on/off
OSV_COLLECTOR_ENABLED = get_env("OSV_COLLECTOR_ENABLED", default="True", is_bool=True)

SNIPPET_CREATION_START_DATE = get_env_date(
    "SNIPPET_CREATION_START", default="2024-07-01"
)
