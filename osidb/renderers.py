"""
Custom content renderers for djangorestframework
"""

import os
import subprocess  # nosec

from django.utils import timezone
from rest_framework.renderers import JSONRenderer

import osidb
from osidb.helpers import get_env


def calc_env(env_str):
    if "prod" in env_str:
        return "prod"
    if "stage" in env_str:
        return "stage"
    return "local"


class OsidbRenderer(JSONRenderer):
    def render(self, data, accepted_media_type=None, renderer_context=None):
        # this custom renderer will inject a couple of meta fields to every
        # response that is sent back for API requests
        if data is None:
            data = {}
        data["dt"] = timezone.now()

        if get_env("OSIDB_RESPONSE_INCLUDE_REV", is_bool=True, default="False"):
            data["revision"] = (
                subprocess.check_output(  # nosec
                    [
                        "git",
                        "rev-parse",
                        "HEAD",
                    ]
                )
                .split()[0]
                .decode()
            )
        else:
            data["revision"] = "unknown"
        data["version"] = osidb.__version__
        data["env"] = calc_env(os.getenv("DJANGO_SETTINGS_MODULE"))
        return super().render(data, accepted_media_type, renderer_context)
