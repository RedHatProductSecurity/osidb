from django.db import migrations, transaction
from django.db.models import Q

from osidb.core import generate_acls

CHUNK_SIZE = 1000


def populate_dt_null_values(apps, schema_editor):
    Affect = apps.get_model("osidb", "Affect")
    AffectEvent = apps.get_model("osidb", "AffectEvent")
    FlawMeta = apps.get_model("osidb", "FlawMeta")
    FlawMetaEvent = apps.get_model("osidb", "FlawMetaEvent")
    FlawComment = apps.get_model("osidb", "FlawComment")
    db_alias = schema_editor.connection.alias

    # For possibly large data migrations Django suggest to turn of the default atomicity
    # of the whole migration and perform the smaller transactions chunks
    # see https://docs.djangoproject.com/en/4.0/howto/writing-migrations/#non-atomic-migrations-1

    while (
        Affect.objects.using(db_alias)
        .filter(Q(created_dt__isnull=True) | Q(updated_dt__isnull=True))
        .exists()
    ):
        with transaction.atomic():
            for affect in Affect.objects.using(db_alias).filter(
                Q(created_dt__isnull=True) | Q(updated_dt__isnull=True)
            )[:CHUNK_SIZE]:
                affect.created_dt = affect.created_dt or affect.flaw.created_dt
                affect.updated_dt = affect.updated_dt or affect.flaw.updated_dt
                affect.save()

    while (
        AffectEvent.objects.using(db_alias)
        .filter(Q(created_dt__isnull=True) | Q(updated_dt__isnull=True))
        .exists()
    ):
        with transaction.atomic():
            for affect_event in AffectEvent.objects.using(db_alias).filter(
                Q(created_dt__isnull=True) | Q(updated_dt__isnull=True)
            )[:CHUNK_SIZE]:
                affect_event.created_dt = (
                    affect_event.created_dt or affect_event.flaw.created_dt
                )
                affect_event.updated_dt = (
                    affect_event.updated_dt or affect_event.flaw.updated_dt
                )
                affect_event.save()

    while (
        FlawMeta.objects.using(db_alias)
        .filter(Q(created_dt__isnull=True) | Q(updated_dt__isnull=True))
        .exists()
    ):
        with transaction.atomic():
            for flaw_meta in FlawMeta.objects.using(db_alias).filter(
                Q(created_dt__isnull=True) | Q(updated_dt__isnull=True)
            )[:CHUNK_SIZE]:
                flaw_meta.created_dt = flaw_meta.created_dt or flaw_meta.flaw.created_dt
                flaw_meta.updated_dt = flaw_meta.updated_dt or flaw_meta.flaw.updated_dt
                flaw_meta.save()

    while (
        FlawMetaEvent.objects.using(db_alias)
        .filter(Q(created_dt__isnull=True) | Q(updated_dt__isnull=True))
        .exists()
    ):
        with transaction.atomic():
            for flaw_meta_event in FlawMetaEvent.objects.using(db_alias).filter(
                Q(created_dt__isnull=True) | Q(updated_dt__isnull=True)
            )[:CHUNK_SIZE]:
                flaw_meta_event.created_dt = (
                    flaw_meta_event.created_dt or flaw_meta_event.flaw.created_dt
                )
                flaw_meta_event.updated_dt = (
                    flaw_meta_event.updated_dt or flaw_meta_event.flaw.updated_dt
                )
                flaw_meta_event.save()

    while FlawComment.objects.using(db_alias).filter(updated_dt__isnull=True).exists():
        with transaction.atomic():
            for flaw_comment in FlawComment.objects.using(db_alias).filter(
                updated_dt__isnull=True
            )[:CHUNK_SIZE]:
                flaw_comment.updated_dt = flaw_comment.created_dt
                flaw_comment.save()


ACLS = ",".join(
    generate_acls(
        [
            "osidb-prod-public-read",
            "osidb-prod-embargo-read",
            "osidb-prod-public-write",
            "osidb-prod-embargo-write",
            "osidb-stage-public-read",
            "osidb-stage-embargo-read",
            "osidb-stage-public-write",
            "osidb-stage-embargo-write",
        ]
    )
)


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("osidb", "0051_stable_ordering"),
    ]

    operations = [
        migrations.RunSQL(f"SET osidb.acl='{ACLS}';", migrations.RunSQL.noop),
        migrations.RunPython(populate_dt_null_values, migrations.RunPython.noop),
    ]
