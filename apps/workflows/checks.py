"""
Workflows entity requirement check definition
"""

import inspect

from django.db import models

from .exceptions import WorkflowDefinitionError


class CheckParser:
    """check description parser"""

    def __init__(self, cls=None):
        """
        instance initializer

        optionally parameterized but by
        default using Flaw as model class
        """
        # import here to prevent cycle
        from osidb.models import Flaw

        self.model = Flaw if cls is None else cls
        assert issubclass(self.model, models.Model)

    ATTRIBUTE_MAP = {
        "cve": "cve_id",
        "cwe": "cwe_id",
        "state": "workflow_state",
        "has_trackers": "trackers_filed",
    }

    # the list of properties which return text choices
    #
    # this cannot be easily inspected programatically
    # but we need to account for the upper-case values
    TEXT_CHOICES_PROPERTIES = [
        "aggregated_impact",
    ]

    def map_attribute(self, attr):
        """maps from external to internal attribute names"""
        if attr in self.ATTRIBUTE_MAP:
            return self.ATTRIBUTE_MAP[attr]

        return attr

    def sanitize_attribute(self, attr):
        """
        taking the raw attribute description
        try to translate it to its real name
        """
        return self.map_attribute(attr.lower())

    def parse(self, check_desc):
        """
        based on the textual check description tries to find a corresponding implementation

        returns:

            (check implementation doc text, check implementation)
            or None if no corresponding implementation
        """
        if isinstance(check_desc, dict):
            return self._parse_dict(check_desc)
        return self._parse_string(check_desc)

    def _parse_string(self, check_desc):
        check_desc = check_desc.replace(" ", "_")
        # enable more human-readable negation
        if check_desc.startswith("is_not_"):
            check_desc = "not_is_" + check_desc[7:]
        check_desc = check_desc.replace("_is_not_", "_not_is_")

        for func in [
            self.desc2property,
            self.desc2not_property,
            self.desc2non_empty,
            # negative equality check must preceed the positive one
            # because of the limitations of the naive syntax parsing
            self.desc2not_equals,
            self.desc2equals,
            self.desc2in,
        ]:
            result = func(check_desc)
            if result is not None:
                return result

        raise WorkflowDefinitionError(
            f"Unknown or incorrect check definition: {check_desc}"
        )

    def _parse_dict(self, check_desc):
        # dict will contain a statement and a list of values, more complex
        # types are not supported
        statement, values = next(iter(check_desc.items()))
        statement = statement.replace(" ", "_")
        for func in [
            self.desc2not_in,
            self.desc2in,
        ]:
            result = func(statement, values)
            if result is not None:
                return result

        raise WorkflowDefinitionError(
            f"Unknown or incorrect check definition: {statement} {', '.join(values)}"
        )

    def desc2property(self, check_desc):
        """native property check"""
        check_desc = self.sanitize_attribute(check_desc)
        if hasattr(self.model, check_desc):
            func = getattr(self.model, check_desc)

            def get_element(instance):
                field = getattr(instance, check_desc)
                return field if not callable(field) else field()

            return (inspect.getdoc(func), get_element)

    def desc2not_property(self, check_desc):
        """negative native property check"""
        if check_desc.startswith("not_"):
            attr = self.sanitize_attribute(check_desc[4:])

            result = self.desc2property(attr)

            if result is not None:
                doc, func = result
                return (
                    f"negative of: {doc}",
                    lambda instance: not func(instance),
                )

    def desc2non_empty(self, check_desc):
        """attribute non-emptiness check"""
        if check_desc.startswith("has_"):
            attr = self.sanitize_attribute(check_desc[4:])
            if hasattr(self.model, attr):
                doc = (
                    f"check that {self.model.__name__} attribute {attr} has a value set"
                )

                def has_element(instance):
                    EMPTY_VALUES = [None, ""]
                    field = getattr(instance, attr)

                    if isinstance(field, models.manager.BaseManager):
                        return field.all().exists()
                    else:
                        return field not in EMPTY_VALUES

                return (doc, has_element)

    def desc2equals(self, check_desc):
        """
        attribute to literal value equality check

        currently only supports string attributes
        which values do not contain any spaces
        """
        if check_desc.count("_is_") == 1:
            attr, value = check_desc.split("_is_")
            attr = self.sanitize_attribute(attr)

            if hasattr(self.model, attr):
                doc = f"check that {self.model.__name__} attribute {attr} has a value equal to {value}"

                def choices_field(model, name):
                    """
                    check and return whether the field given by
                    name is a field with choices on the model
                    """
                    if name not in [f.name for f in model._meta.get_fields()]:
                        return False
                    return model._meta.get_field(name).choices is not None

                # model fields with defined choices require uppercase letters
                if (
                    choices_field(self.model, attr)
                    or attr in self.TEXT_CHOICES_PROPERTIES
                ):
                    value = value.upper()

                def compare_element(instance):
                    field = getattr(instance, attr)
                    return (field if not callable(field) else field()) == value

                return (doc, compare_element)

    def desc2not_equals(self, check_desc):
        """
        negative attribute to literal value comparison check

        currently only supports string attributes
        which values do not contain any spaces
        """
        if check_desc.count("_not_is_") == 1:
            check_desc = check_desc.replace("_not_is_", "_is_")

            result = self.desc2equals(check_desc)

            if result is not None:
                doc, func = result
                return (
                    f"negative of: {doc}",
                    lambda instance: not func(instance),
                )

    def desc2in(self, statement, values):
        if statement.count("_in") == 1:
            attr = self.sanitize_attribute(statement[:-3])

            if hasattr(self.model, attr):
                doc = f"check that {self.model.__name__} attribute {attr} is in [{', '.join(values)}]"

                def check_inclusion(instance):
                    field = getattr(instance, attr)
                    return (field if not callable(field) else field()) in values

                return (doc, check_inclusion)

    def desc2not_in(self, statement, values):
        if statement.count("_not_in") == 1:
            statement = statement.replace("_not_in", "_in")
            result = self.desc2in(statement, values)
            if result is not None:
                doc, func = result
                return (
                    f"negative of: {doc}",
                    lambda instance: not func(instance),
                )
