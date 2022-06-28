"""
    osidb exceptions
"""


class OSIDBException(Exception):
    """Base Exception class for osidb specific exceptions"""


class DataInconsistencyException(OSIDBException):
    """Data Inconsistency Exception"""
