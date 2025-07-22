"""
collector constants
"""

from osidb.helpers import get_env

COLLECTOR_API_VERSION: str = "v1"
COLLECTOR_DRY_RUN: bool = get_env("DRY_RUN", default="False", is_bool=True)

CRONTAB_PARAMS_NAMES = [
    "minute",
    "hour",
    "day_of_month",
    "month_of_year",
    "day_of_week",
]
