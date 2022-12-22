"""
BBSync constants
"""
import os

from collectors.bzimport.constants import BZ_DT_FMT_HISTORY

DATE_FMT = "%Y-%m-%d"
# these two time formats are the same
# thus spare us defining it again
DATETIME_FMT = BZ_DT_FMT_HISTORY

# JSON schema for SRT notes flaw metadata
SRTNOTES_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "./srtnotes-schema.json")
