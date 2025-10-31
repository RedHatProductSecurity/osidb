"""
Helpers for direct or development shell usage
"""

import json
import logging
import logging.handlers
import re
import ssl
import sys
import warnings
from os import getenv
from typing import Any, Callable, List, Type, Union, cast

from celery._state import get_current_task
from django.conf import settings
from django.db import models
from django.utils.timezone import datetime, make_aware
from django_deprecate_fields import DeprecatedField, logger
from requests.exceptions import JSONDecodeError
from requests.models import Response
from rest_framework.exceptions import ValidationError
from rest_framework.request import Request

from osidb.core import set_user_acls
from osidb.validators import CVE_RE_STR, restrict_regex

from .exceptions import OSIDBException


def cve_id_comparator(cve_id: str) -> tuple[int, int]:
    """
    comparator to sort CVE IDs by

        1) the year
        2) the sequence
    """
    _, year, seq = cve_id.split("-", maxsplit=2)
    return int(year), int(seq)


def differ(instance1, instance2, attributes):
    """
    boolean check whether the given instances
    have any differences in the given attributes

    the caller is responsible for making sure that
    the given instances really have the attributes
    """
    for attribute in attributes:
        if getattr(instance1, attribute) != getattr(instance2, attribute):
            return True
    return False


def ensure_list(item):
    """
    helper to ensure that the item is list
    """
    return item if isinstance(item, list) else [item]


def filter_cves(strings, inverse=False):
    """
    CVE strings filter helper
    """
    return (
        [s for s in strings if not re.match(restrict_regex(CVE_RE_STR), s)]
        if inverse
        else [s for s in strings if re.match(restrict_regex(CVE_RE_STR), s)]
    )


def get_flaw_or_404(pk, queryset=None):
    """
    get flaw instance or raise HTTP 404 error
    """
    from django.http import Http404

    from osidb.models import Flaw

    try:
        return Flaw.objects.get_by_identifier(pk, queryset=queryset)
    except Flaw.DoesNotExist as e:
        raise Http404 from e


# Replaces strtobool from the deprecated distutils library
def strtobool(val: str):
    val = val.lower()
    if val in {"y", "yes", "t", "true", "on", "1"}:
        return True
    elif val in {"n", "no", "f", "false", "off", "0"}:
        return False

    raise ValueError(f"invalid truth value {val}")


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
        value = strtobool(value)
    if is_int:
        value = int(value)
    if is_json:
        value = json.loads(value)

    return value


def get_env_date(key: str, default: str) -> Union[datetime, None]:
    """get a date environment variable of the ISO format (YYYY-MM-DD)"""
    value = getenv(key, default)
    # consider empty string as empty value
    # as setting the value to non-existing env variable
    # in compose.yml results in an empty string
    if value == "":
        value = default
    return make_aware(datetime.fromisoformat(value))


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


def get_mixin_subclases(mixin):
    """Gets all non-abstract models that inherit from a mixin."""
    result = []
    for subclass in mixin.__subclasses__():
        if subclass._meta.abstract:
            result.extend(get_mixin_subclases(subclass))
        else:
            result.append(subclass.__name__)
    return result


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


def safe_get_response_content(response: Response):
    """
    Returns either JSON or plaintext response content based
    on the response content type
    """
    try:
        return response.json()
    except JSONDecodeError:
        return response.text


class JSONSocketHandler(logging.handlers.SocketHandler):
    """
    Custom Socket handler class for JSON formatting and TLS/SSL support
    """

    def __init__(self, *args, logfile: str, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.logfile = logfile

    def makePickle(self, record: logging.LogRecord) -> bytes:
        """
        Pickles the formatted record in binary format and makes it ready for
        transimission. Adds information about destination logfile.
        """
        formatted_record = self.formatter.format(record)
        record_json = {"formatted_record": formatted_record, "logfile": self.logfile}
        encoded_json = f"{json.dumps(record_json)}\n".encode(encoding="utf-8")
        return encoded_json

    def makeSocket(self, *args, **kwargs):
        """
        A factory method which allows subclasses to define the precise
        type of socket they want with TLS/SSL support.
        """

        result = super().makeSocket(*args, *kwargs)

        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations(
            cafile="/opt/app-root/etc/logstash/certs/osidb-logstash-ca.crt"
        )
        context.load_cert_chain(
            certfile="/opt/app-root/etc/logstash/certs/osidb-logstash.crt",
            keyfile="/opt/app-root/etc/logstash/certs/osidb-logstash.key",
        )

        result = context.wrap_socket(result, server_hostname=self.address[0])
        return result


def bypass_rls(f: Callable) -> Callable:
    """
    Bypass Row-Level Security checks in the database.

    When a callable is decorated with this helper, the ACLs will be set to
    ALL_GROUPS, effectively bypassing Row-Level Security / Authorization.

    Be aware of the implications of bypassing RLS, namely that any actions
    that depend on a user's permissions will not work correctly if executed
    within the lifetime of the callable that this decorator wraps.

    Should be used with system-driven processes mostly:
        * Migrations
        * Collectors & Scheduled tasks
        * Non user-driven processes
    """

    def wrapped(*args, **kwargs):
        set_user_acls(settings.ALL_GROUPS)
        f(*args, **kwargs)
        set_user_acls([])

    return wrapped


def get_execution_env() -> str:
    """
    Returns the current execution environment for the running Django app.

    e.g. local, stage, prod, ci
    """
    return getenv("DJANGO_SETTINGS_MODULE", "").split("_")[-1]


def get_bugzilla_api_key(request: Request) -> str:
    """
    Checks that a user-provided Bugzilla API token exists and returns it.

    The token can either be provided through the Bugzilla-Api-Key HTTP header
    on each request or it can be retrieved from the integrations store if the
    user has previously stored it using PATCH /osidb/integrations.
    """
    from django.contrib.auth.models import User

    from osidb.integrations import IntegrationRepository, IntegrationSettings

    # explicitly passed-through token takes precedence
    if not (bz_api_key := request.META.get("HTTP_BUGZILLA_API_KEY")):
        integration_settings = IntegrationSettings()
        integration_repo = IntegrationRepository(integration_settings)
        user = cast(User, request.user)
        bz_api_key = integration_repo.read_bz_token(user.username)

    if not bz_api_key:
        raise ValidationError(
            {
                "Bugzilla-Api-Key": "This HTTP header is required or token must be stored via /osidb/integrations"
            }
        )

    return bz_api_key


def get_jira_api_key(request: Request) -> str:
    """
    Checks that a user-provided JIRA API token exists and returns it.

    The token can either be provided through the Jira-Api-Key HTTP header
    on each request or it can be retrieved from the integrations store if the
    user has previously stored it using PATCH /osidb/integrations.
    """
    from django.contrib.auth.models import User

    from osidb.integrations import IntegrationRepository, IntegrationSettings

    # explicitly passed-through token takes precedence
    if not (jira_api_key := request.META.get("HTTP_JIRA_API_KEY")):
        integration_settings = IntegrationSettings()
        integration_repo = IntegrationRepository(integration_settings)
        user = cast(User, request.user)
        jira_api_key = integration_repo.read_jira_token(user.username)

    if not jira_api_key:
        raise ValidationError(
            {
                "Jira-Api-Key": "This HTTP header is required or token must be stored via /osidb/integrations"
            }
        )

    return jira_api_key
