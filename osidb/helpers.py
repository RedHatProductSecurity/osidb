"""
Helpers for direct or development shell usage
"""

import json
import logging
import re
import sys
import warnings
from distutils.util import strtobool
from os import getenv
from typing import Any, List, Type, Union

from celery._state import get_current_task
from django.db import models
from django_deprecate_fields import DeprecatedField, logger

from .exceptions import OSIDBException


def cve_id_comparator(cve_id: str) -> tuple[int, int]:
    """
    comparator to sort CVE IDs by

        1) the year
        2) the sequence
    """
    _, year, seq = cve_id.split("-", maxsplit=2)
    return int(year), int(seq)


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


def ps_update_stream_natural_keys(values):
    """Sort alphanumeric strings
    http://nedbatchelder.com/blog/200712/human_sorting.html
    """
    if not values:
        return []

    def atoi(text):
        return int(text) if text.isdigit() else text

    return [atoi(c) for c in re.split(r"(\d+)", values.name)]


# Part of the following code is subject to a different license and copyright
# holder:

# Copyright 2018 3YOURMIND GmbH

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


class DynamicDeprecatedField(DeprecatedField):
    """
    This override allows a return_instead callable with argument.
    """

    def __get__(self, obj, type=None):
        msg = "accessing deprecated field %s.%s" % (
            obj.__class__.__name__,
            self._get_name(obj),
        )
        warnings.warn(msg, DeprecationWarning, stacklevel=2)
        logger.warning(msg)
        if not callable(self.val):
            return self.val
        # this version of the code, when compared to the original, makes it
        # so that if val is callable, its output can depend on the Model object
        # instance
        try:
            return self.val(obj)
        except TypeError:
            # the callable that was passed does not support any arguments
            return self.val()


def deprecate_field(field_instance, return_instead=None):
    """
    Can be used in models to delete a Field in a Backwards compatible manner.
    The process for deleting old model Fields is:
    1. Mark a field as deprecated by wrapping the field with this function
    2. Wait until (1) is deployed to every relevant server/branch
    3. Delete the field from the model.

    For (1) and (3) you need to run ./manage.py makemigrations:
    :param field_instance: The field to deprecate
    :param return_instead: A value or function that
    the field will pretend to have
    """
    # this version of the code, when compared to the original, makes use
    # of DynamicDeprecatedField instead of DeprecatedField.
    if not set(sys.argv) & {"makemigrations", "migrate", "showmigrations"}:
        return DynamicDeprecatedField(return_instead)

    field_instance.null = True
    return field_instance
