"""
Data migration from old label models (FlawLabel, FlawCollaborator) to the new
polymorphic V2 models (FlawLabelV2 hierarchy and definition tables).

1. FlawLabel definitions → BULabelDefinition, CollaboratorLabelDefinition,
   ProductFamilyLabelDefinition
2. FlawCollaborator instances → AliasLabel, BULabel, CollaboratorLabel,
   ProductFamilyLabel, WorkflowLabel
"""

import uuid

from django.db import migrations

BATCH_SIZE = 1000


def migrate_definitions(apps, schema_editor):
    """Migrate FlawLabel definitions to V2 definition tables."""
    FlawLabel = apps.get_model("osidb", "FlawLabel")
    BULabelDefinition = apps.get_model("osidb", "BULabelDefinition")
    CollaboratorLabelDefinition = apps.get_model("osidb", "CollaboratorLabelDefinition")
    ProductFamilyLabelDefinition = apps.get_model(
        "osidb", "ProductFamilyLabelDefinition"
    )

    for fl in FlawLabel.objects.all():
        if fl.type == "context_based":
            CollaboratorLabelDefinition.objects.get_or_create(
                name=fl.name,
                defaults={"uuid": uuid.uuid4()},
            )
        elif fl.type == "bu":
            BULabelDefinition.objects.get_or_create(
                name=fl.name,
                defaults={"uuid": uuid.uuid4()},
            )
        elif fl.type == "product_family":
            ProductFamilyLabelDefinition.objects.get_or_create(
                name=fl.name,
                defaults={
                    "uuid": uuid.uuid4(),
                    "ps_components": fl.ps_components,
                    "ps_modules": fl.ps_modules,
                    "ps_components_exclude": fl.ps_components_exclude,
                    "ps_modules_exclude": fl.ps_modules_exclude,
                },
            )


def migrate_labels(apps, schema_editor):
    """Migrate FlawCollaborator instances to V2 label tables."""
    ContentType = apps.get_model("contenttypes", "ContentType")
    FlawCollaborator = apps.get_model("osidb", "FlawCollaborator")
    FlawLabelV2 = apps.get_model("osidb", "FlawLabelV2")
    AliasLabel = apps.get_model("osidb", "AliasLabel")
    BULabel = apps.get_model("osidb", "BULabel")
    CollaboratorLabel = apps.get_model("osidb", "CollaboratorLabel")
    ProductFamilyLabel = apps.get_model("osidb", "ProductFamilyLabel")
    WorkflowLabel = apps.get_model("osidb", "WorkflowLabel")

    ct_alias = ContentType.objects.get_for_model(AliasLabel)
    ct_bu = ContentType.objects.get_for_model(BULabel)
    ct_collab = ContentType.objects.get_for_model(CollaboratorLabel)
    ct_pf = ContentType.objects.get_for_model(ProductFamilyLabel)
    ct_workflow = ContentType.objects.get_for_model(WorkflowLabel)

    type_config = {
        "alias": (AliasLabel, ct_alias, []),
        "bu": (BULabel, ct_bu, ["state", "contributor", "relevant"]),
        "context_based": (
            CollaboratorLabel,
            ct_collab,
            ["state", "contributor", "relevant"],
        ),
        "product_family": (ProductFamilyLabel, ct_pf, ["relevant"]),
        "workflow": (WorkflowLabel, ct_workflow, []),
    }

    for fc in FlawCollaborator.objects.all().iterator(chunk_size=BATCH_SIZE):
        if FlawLabelV2.objects.filter(flaw_id=fc.flaw_id, name=fc.label).exists():
            continue

        config = type_config.get(fc.type)
        if config is None:
            continue

        subclass_model, content_type, extra_fields = config

        base = FlawLabelV2.objects.create(
            uuid=fc.uuid,
            flaw_id=fc.flaw_id,
            name=fc.label,
            created_dt=fc.created_dt,
            updated_dt=fc.updated_dt,
            polymorphic_ctype=content_type,
        )

        sub_kwargs = {"flawlabelv2_ptr": base}
        for field in extra_fields:
            sub_kwargs[field] = getattr(fc, field)

        subclass_model.objects.create(**sub_kwargs)


class Migration(migrations.Migration):
    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("osidb", "0242_polymorphic_labels"),
    ]

    operations = [
        migrations.RunPython(
            migrate_definitions,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.RunPython(
            migrate_labels,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
