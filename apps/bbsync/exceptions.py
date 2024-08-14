"""
BBSync exceptions
"""


class ProductDataError(Exception):
    """
    product data error exception class
    for error in either the data or the product definitions
    """


class UnsavableModelError(Exception):
    """
    error caused by attempt to save a model which cannot be saved
    """


class UnsaveableFlawError(UnsavableModelError):
    """
    error caused by attempt to save a flaw which cannot be saved
    either by its nature or due to the current saver capabilities
    """
