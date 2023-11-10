from osidb.helpers import get_env

SNIPPET_CREATION_ENABLED = get_env("SNIPPET_CREATION", default="False", is_bool=True)
