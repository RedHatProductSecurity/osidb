"""
Workflows entity requirement check definition
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
        "is_major_incident": "is_major_incident_temp",
        "cve": "cve_id",
        "cwe": "cwe_id",
        "group": "group_key",
        "state": "workflow_state",
        "team": "team_id",
        "trackers": "trackers_filed",
    }

    @classmethod
    def map_attribute(cls, attr):
        """maps from external to internal attribute names"""
        if attr in cls.ATTRIBUTE_MAP:
            return cls.ATTRIBUTE_MAP[attr]

        return attr

    @classmethod
    def sanitize_attribute(cls, attr):
        """
        taking the raw attribute description
        try to translate it to its real name
        """
        return cls.map_attribute(attr.lower())

    @classmethod
    def parse(cls, check_desc):
        """
        based on the textual check description tries to find a corresponding implementation

        returns:

            (check implementation doc text, check implementation)
            or None if no corresponding implementation
        """
        check_desc = check_desc.replace(" ", "_")
        # enable more human-readable negation
        if check_desc.startswith("is_not_"):
            check_desc = "not_is_" + check_desc[7:]
        check_desc = check_desc.replace("_is_not_", "_not_is_")

        for func in [
            cls.desc2property,
            cls.desc2not_property,
            cls.desc2non_empty,
            # negative equality check must preceed the positive one
            # because of the limitations of the naive syntax parsing
            cls.desc2not_equals,
            cls.desc2equals,
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
        check_desc = cls.sanitize_attribute(check_desc)
        if hasattr(cls.model, check_desc):
            func = getattr(cls.model, check_desc)

            def get_element(instance):
                field = getattr(instance, check_desc)
                return field if not callable(field) else field()

            return (inspect.getdoc(func), get_element)

    @classmethod
    def desc2not_property(cls, check_desc):
        """negative native property check"""
        if check_desc.startswith("not_"):
            attr = cls.sanitize_attribute(check_desc[4:])

            result = cls.desc2property(attr)

            if result is not None:
                doc, func = result
                return (
                    f"negative of: {doc}",
                    lambda instance: not func(instance),
                )

    @classmethod
    def desc2non_empty(cls, check_desc):
        """attribute non-emptiness check"""
        if check_desc.startswith("has_"):
            attr = cls.sanitize_attribute(check_desc[4:])
            if hasattr(cls.model, attr):
                doc = (
                    f"check that {cls.model.__name__} attribute {attr} has a value set"
                )

                def has_element(instance):
                    EMPTY_VALUES = [None, ""]
                    field = getattr(instance, attr)

                    if isinstance(field, models.manager.BaseManager):
                        return field.all().exists()
                    else:
                        return field not in EMPTY_VALUES

                return (doc, has_element)

    @classmethod
    def desc2equals(cls, check_desc):
        """
        attribute to literal value equality check

        currently only supports string attributes
        which values do not contain any spaces
        """
        if check_desc.count("_is_") == 1:
            attr, value = check_desc.split("_is_")
            attr = cls.sanitize_attribute(attr)

            if hasattr(cls.model, attr):
                doc = f"check that {cls.model.__name__} attribute {attr} has a value equal to {value}"

                # model fields with defined choices require uppercase letters
                if getattr(getattr(getattr(cls.model, attr), "field"), "choices"):
                    value = value.upper()

                def compare_element(instance):
                    field = getattr(instance, attr)
                    return (field if not callable(field) else field()) == value

                return (doc, compare_element)

    @classmethod
    def desc2not_equals(cls, check_desc):
        """
        negative attribute to literal value comparison check

        currently only supports string attributes
        which values do not contain any spaces
        """
        if check_desc.count("_not_is_") == 1:
            check_desc = check_desc.replace("_not_is_", "_is_")

            result = cls.desc2equals(check_desc)

            if result is not None:
                doc, func = result
                return (
                    f"negative of: {doc}",
                    lambda instance: not func(instance),
                )
