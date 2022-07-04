"""
Bugzilla import exceptions
"""


class BZImportException(Exception):
    """Base Exception class for bzimport specific exceptions"""


class RecoverableBZImportException(BZImportException):
    """
    temporary exceptions to be recovered by a rerun
    may be network issues or backend outages etc.
    """


class NonRecoverableBZImportException(BZImportException):
    """
    permanent exceptions consistent between runs
    may be malformed data or unhandled conditions etc.
    """
