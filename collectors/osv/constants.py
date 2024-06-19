from osidb.helpers import get_env

# Switch to turn the collector on/off
OSV_COLLECTOR_ENABLED = get_env("OSV_COLLECTOR_ENABLED", default="True", is_bool=True)
