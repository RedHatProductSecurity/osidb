from osidb.helpers import get_env, get_env_date

SNIPPET_CREATION_ENABLED = get_env("SNIPPET_CREATION", default="False", is_bool=True)
SNIPPET_CREATION_START_DATE = get_env_date("SNIPPET_CREATION_START")
