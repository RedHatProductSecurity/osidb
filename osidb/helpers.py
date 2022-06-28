"""
Helpers for direct or development shell usage
"""

import json
from distutils.util import strtobool
from os import getenv
from typing import Any, List, Type, Union

from django.db import models

from .exceptions import OSIDBException


def get_env(
    key: str,
    default: Union[None, str] = None,
    is_bool: bool = False,
    is_json: bool = False,
) -> Any:
    """get environment variable"""
    if is_bool and is_json:
        raise OSIDBException(
            "Expected environment variable type cannot be both Boolean and JSON at the same time"
        )

    value = getenv(key, default)
    # consider empty string as empty value
    # as setting the value to non-existing env variable
    # in compose.yml results in an empty string
    if value == "":
        value = default

    if is_bool:
        value = bool(strtobool(value))
    if is_json:
        value = json.loads(value)

    return value


def get_unique_meta_attr_keys(model: Type[models.Model]) -> List[str]:
    """Get all unique meta_attr keys which currently exist in database"""

    try:
        model._meta.get_field("meta_attr")
    except models.FieldDoesNotExist:
        return []

    keys_tuples = model.objects.values_list("meta_attr__keys")
    keys_sets = map(lambda x: set(x[0]), keys_tuples)
    unique_meta_attr_keys = list(set().union(*keys_sets))
    return sorted(unique_meta_attr_keys)


def get_model_fields(model: Type[models.Model]) -> List[str]:
    """Get all field names of the model"""
    return [field.name for field in model._meta.get_fields()]
