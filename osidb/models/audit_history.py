import json
from functools import cache

from django.apps import apps
from django.db import models
from pghistory import models as pg_models


def normalize_pgh_context(value):
    if isinstance(value, (bytes, bytearray)):
        value = value.decode()
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def pgh_data_from_row(audit_table, row):
    excluded = {"acl_read", "acl_write", "pgh_context", "pgh_context_id"}
    return {
        column: row[column]
        for column in audit_table["columns"]
        if not column.startswith("pgh_") and column not in excluded
    }


def pgh_diff(previous_data, pgh_data):
    diff = {}
    for key, value in pgh_data.items():
        if previous_data.get(key) != value:
            diff[key] = [previous_data.get(key), value]
    return diff


def audit_model_for_model(model_class):
    try:
        return apps.get_model(
            model_class._meta.app_label,
            f"{model_class._meta.object_name}Audit",
        )
    except LookupError:
        return None


def audit_table_for_model(model_class):
    audit_model = audit_model_for_model(model_class)
    if audit_model is None:
        return None

    return {
        "model": audit_model,
        "audit_label": audit_model._meta.label,
        "object_label": model_class._meta.label,
        "columns": [field.attname for field in audit_model._meta.concrete_fields],
    }


@cache
def registered_audit_tables():
    audit_tables = []
    for model in apps.get_models():
        fields = {field.attname for field in model._meta.fields}
        if not {"pgh_id", "pgh_obj_id", "pgh_created_at"}.issubset(fields):
            continue
        if not model._meta.object_name.endswith("Audit"):
            continue
        try:
            object_label = model._meta.get_field(
                "pgh_obj"
            ).remote_field.model._meta.label
        except Exception:
            object_label = model._meta.label.removesuffix("Audit")
        audit_tables.append(
            {
                "model": model,
                "audit_label": model._meta.label,
                "object_label": object_label,
                "columns": [field.attname for field in model._meta.concrete_fields],
            }
        )
    return tuple(audit_tables)


def audit_rows_with_context(queryset, audit_table):
    rows = queryset.values(*audit_table["columns"], "pgh_context__metadata")
    for row in rows:
        row["pgh_context"] = row.pop("pgh_context__metadata")
        yield row


class CustomHistoryBase(pg_models.Event):
    """
    Base model for all pghistory event tables
    """

    class Meta:
        abstract = True
        indexes = [
            models.Index(
                fields=["pgh_obj_id", "-pgh_created_at"],
                name="idx_%(class)s_obj_lookup",
            ),
        ]
