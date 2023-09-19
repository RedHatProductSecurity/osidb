"""
OSIM entity requirement check definition
"""
import inspect

from django.db import models

from .exceptions import WorkflowDefinitionError


class MetaCheckParser(type):
    """
    meta-class to define class property to emultate class constant

    this dance happens because of the hard-to-prevent cycle we have in the dependencies

    Flaw is based on WorkflowModel which uses WorkflowFramework which contains
    Workflow model which contains Check which calls CheckParser which would like to have
    model class constant - at least for now - containing Flaw class
    """

    @property
    def model(cls):
        """model class property"""
        # import here to prevent cycle
        from osidb.models import Flaw

        # constant model for now
        # generalize when needed
        return Flaw


class CheckParser(metaclass=MetaCheckParser):
    """check description parser"""

    ATTRIBUTE_MAP = {
        "major_incident": "is_major_incident",
        "cve": "cve_id",
        "cwe": "cwe_id",
    }

    @classmethod
    def map_attribute(cls, attr):
        """maps from external to internal attribute names"""
        if attr in cls.ATTRIBUTE_MAP:
            return cls.ATTRIBUTE_MAP[attr]

        return attr

    @classmethod
    def parse(cls, check_desc):
        """
        based on the textual check description tries to find a corresponding implementation

        returns:

            (check implementation doc text, check implementation)
            or None if no corresponding implementation
        """
        check_desc = check_desc.lower().replace(" ", "_")

        for func in [
            cls.desc2property,
            cls.desc2not_property,
            cls.decs2non_empty,
        ]:
            result = func(check_desc)
            if result is not None:
                return result

        raise WorkflowDefinitionError(
            f"Unknown or incorrect check definition: {check_desc}"
        )

    @classmethod
    def desc2property(cls, check_desc):
        """native property check"""
        check_desc = cls.map_attribute(check_desc)
        if hasattr(cls.model, check_desc):
            func = getattr(cls.model, check_desc)
            return (
                inspect.getdoc(func),
                lambda instance: getattr(instance, check_desc),
            )

    @classmethod
    def desc2not_property(cls, check_desc):
        """negative native property check"""
        if check_desc.startswith("not_"):
            attr = cls.map_attribute(check_desc[4:])

            result = cls.desc2property(attr)

            if result is not None:
                doc, func = result
                return (
                    f"negative of: {doc}",
                    lambda instance: not func(instance),
                )

    @classmethod
    def decs2non_empty(cls, check_desc):
        """attribute non-emptiness check"""
        if check_desc.startswith("has_"):
            attr = cls.map_attribute(check_desc[4:])
            if hasattr(cls.model, attr):
                message = (
                    f"check that {cls.model.__name__} attribute {attr} has a value set"
                )

                def has_element(instance):
                    EMPTY_VALUES = [None, ""]
                    field = getattr(instance, attr)

                    if isinstance(field, models.manager.BaseManager):
                        return field.all().exists()
                    else:
                        return field not in EMPTY_VALUES

                return (message, has_element)
