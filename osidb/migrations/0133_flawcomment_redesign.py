from django.db import migrations, models
from django.conf import settings

from osidb.core import set_user_acls


BATCH_SIZE = 1000


def forwards_func(apps, schema_editor):
    set_user_acls(settings.ALL_GROUPS)
    FlawComment = apps.get_model("osidb", "FlawComment")

    # Move existing comment data from meta_attr to the model
    comments = FlawComment.objects.all().iterator(chunk_size=BATCH_SIZE)

    batch = []
    for i, comment in enumerate(comments, 1):
        comment.creator = comment.meta_attr.get("creator", "")
        # is_private seems to be stored as either a string ("True", "False") or
        # as a bool in old data, so check both cases
        is_private = comment.meta_attr.get("is_private", False)
        if isinstance(is_private, str):
            is_private = is_private == "True"
        elif not isinstance(is_private, bool):
            # Just in case we have something else...
            is_private = False
        comment.is_private = is_private
        batch.append(comment)
        if i % BATCH_SIZE == 0:
            FlawComment.objects.bulk_update(batch, ["creator", "is_private"])
            batch = []
    if batch:
        FlawComment.objects.bulk_update(batch, ["creator", "is_private"])


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0132_remove_flaw_state"),
    ]

    operations = [
        migrations.AddField(
            model_name="flawcomment",
            name="creator",
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name="flawcomment",
            name="is_private",
            field=models.BooleanField(default=False),
        ),
        migrations.RunPython(forwards_func, migrations.RunPython.noop, atomic=True),
    ]
