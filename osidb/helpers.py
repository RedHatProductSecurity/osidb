"""
Helpers for direct or development shell usage
"""

import json
import logging
from distutils.util import strtobool
from os import getenv
from typing import Any, List, Type, Union

from celery._state import get_current_task
from django.conf import settings
from django.db import models
from rest_framework.viewsets import ViewSet

from .exceptions import OSIDBException


def ensure_list(item):
    """
    helper to ensure that the item is list
    """
    return item if isinstance(item, list) else [item]


def get_env(
    key: str,
    default: Union[None, str] = None,
    is_bool: bool = False,
    is_int: bool = False,
    is_json: bool = False,
) -> Any:
    """get environment variable"""
    if (is_bool and is_int) or (is_bool and is_json) or (is_int and is_json):
        raise OSIDBException(
            "Expected environment variable cannot be of multiple types at the same time"
        )

    value = getenv(key, default)
    # consider empty string as empty value
    # as setting the value to non-existing env variable
    # in compose.yml results in an empty string
    if value == "":
        value = default

    if is_bool:
        value = bool(strtobool(value))
    if is_int:
        value = int(value)
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


class TaskFormatter(logging.Formatter):
    """
    Custom formatter based on celery 'celery.utils.log.TaskFormatter'
    which injects the 'task_name' and 'task_id' into the logs whenever
    the logs are emitted during the Celery task execution
    """

    def format(self, record):
        task = get_current_task()
        if task and task.request:
            # Executed inside Celery task - inject task_name and task_id
            record.__dict__.update(task_id=f"[{task.request.id}]", task_name=task.name)
        else:
            # Executed outside Celery task - use name isntead of the task_name
            # and omit the task_id
            record.__dict__.setdefault("task_name", record.__dict__.get("name"))
            record.__dict__.setdefault("task_id", "")
        return super().format(record)


def get_valid_http_methods(cls: ViewSet, excluded: list[str] = None) -> list[str]:
    """
    Removes blacklisted and unsafe HTTP methods from a view if necessary.
    Optionally also removes given excluded methods.

    Blacklisted HTTP methods can be defined in the django settings, unsafe HTTP
    methods will be removed if the app is running in read-only mode, by setting
    the OSIDB_READONLY_MODE env variable to "1".

    :param cls: The ViewSet class from which http_method_names are inherited
    :param excluded: A list of exlicitly excluded HTTP methods.
    :return: A list of valid HTTP methods that a ViewSet will accept
    """
    base_methods = cls.http_method_names
    excluded_methods = [] if excluded is None else excluded
    unsafe_methods = (
        "patch",
        "post",
        "put",
        "delete",
        "connect",
        "trace",
    )
    valid_methods = []
    for method in base_methods:
        if method in excluded_methods:
            continue
        if method in settings.BLACKLISTED_HTTP_METHODS:
            continue
        if settings.READONLY_MODE and method in unsafe_methods:
            continue
        valid_methods.append(method)
    return valid_methods
