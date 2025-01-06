from osidb.helpers import get_env, get_env_date

# Switch to turn the collector on/off
OSV_COLLECTOR_ENABLED = get_env("OSV_COLLECTOR_ENABLED", default="True", is_bool=True)

OSV_START_DATE = get_env_date("OSV_START_DATE", default="2024-07-01")
