from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0254_reclassify_analysis_flaws"),
    ]

    operations = [
        migrations.DeleteModel(
            name="Erratum",
        ),
    ]
