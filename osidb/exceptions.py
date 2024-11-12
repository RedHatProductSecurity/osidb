"""
    osidb exceptions
"""
from rest_framework import status


class OSIDBException(Exception):
    """Base Exception class for osidb specific exceptions"""


class DataInconsistencyException(OSIDBException):
    """Data Inconsistency Exception"""

    http_code = status.HTTP_409_CONFLICT


class InvalidTestEnvironmentException(OSIDBException):
    """Invalid Test Environment Exception"""
