"""
Remove stale ContentType entries for deleted FlawCollaborator and FlawLabelV2 models.

## The Problem

After migration 0258 deleted the FlawCollaborator model and renamed FlawLabelV2 to
FlawLabel, the corresponding django_content_type entries were not cleaned up. This
causes "relation osidb_flawcollaborator does not exist" errors when querying
/api/v2/flaws with 'labels' in include_fields.

## Root Cause - The Smoking Gun

The error traceback shows:
```
File "django/db/models/query.py", line 2408, in prefetch_related_objects
File "django/db/models/query.py", line 2572, in prefetch_one_level
File "django/db/models/fields/related_descriptors.py", line 800, in get_prefetch_querysets
...
ProgrammingError: relation "osidb_flawcollaborator" does not exist
```

When Django's ORM executes `prefetch_related('labels')` on Flaw objects, the
polymorphic query manager discovers ALL ContentType entries that could be related
to the FlawLabel polymorphic hierarchy. Because the stale 'flawcollaborator'
ContentType still exists in django_content_type, Django's polymorphic machinery
attempts to include it in the query, generating SQL that references the deleted
osidb_flawcollaborator table.

Even though NO actual label records have polymorphic_ctype_id pointing to these
stale ContentTypes, Django's query construction phase still tries to JOIN or
reference the tables based on the ContentType metadata alone.

## Safety Verification (from stage environment)

Query results confirmed NO records reference these ContentTypes:
- ContentType 147 (flawcollaborator): 0 label records, 0 audit records
- ContentType 324 (flawlabelv2): 0 label records, 0 audit records

All 35,738 actual label records correctly use the new ContentTypes:
- aliaslabel (339): 848 records
- bulabel (340): 10 records
- productfamilylabel (342): 6,885 records
- workflowlabel (343): 27,995 records

## Note on FlawLabelV2Audit ContentType

The 'flawlabelv2audit' ContentType (id 73) is intentionally KEPT because:
1. The audit table osidb_flawlabelv2audit still exists (not renamed)
2. It's referenced in pghistory tracking (see model_name="FlawLabelV2Audit" in label.py)
3. It's not part of the polymorphic query hierarchy that causes the error
"""

from django.db import migrations


def remove_stale_contenttypes(apps, schema_editor):
    """
    Remove ContentType entries for FlawCollaborator and FlawLabelV2.

    These models were deleted/renamed in migration 0258 but their ContentType
    entries remained, causing polymorphic queries to fail with "relation does not exist".
    """
    ContentType = apps.get_model("contenttypes", "ContentType")

    # Delete FlawCollaborator ContentType (V1 model deleted in migration 0258)
    deleted_count, _ = ContentType.objects.filter(
        app_label="osidb",
        model="flawcollaborator"
    ).delete()

    if deleted_count > 0:
        print(f"Deleted {deleted_count} flawcollaborator ContentType entry")

    # Delete FlawLabelV2 ContentType (renamed to FlawLabel in migration 0258)
    deleted_count, _ = ContentType.objects.filter(
        app_label="osidb",
        model="flawlabelv2"
    ).delete()

    if deleted_count > 0:
        print(f"Deleted {deleted_count} flawlabelv2 ContentType entry")


class Migration(migrations.Migration):

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("osidb", "0260_cleanup_stale_alerts"),
    ]

    operations = [
        migrations.RunPython(
            remove_stale_contenttypes,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
