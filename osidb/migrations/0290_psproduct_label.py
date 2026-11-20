from django.db import migrations, models

# The former hard-coded list of service products (removed from osidb.constants
# together with the switch to the product-definitions `label` attribute). It is
# inlined here so this migration stays self-contained and reproducible.
LEGACY_SERVICES_PRODUCTS = [
    "ansible-services",
    "cloud-redhat-com",
    "hosted-openshift",
    "insights",
    "managed-application-services",
    "other-services",
    "openshift-hosted",
    "hostedservices",
]


def populate_labels(apps, schema_editor):
    """
    Backfill the new `label` field from the previous classification so that
    existing products keep their middleware/service behaviour during the
    transition, until product definitions start providing `label` and the
    product_definitions collector repopulates the products.
    """
    PsProduct = apps.get_model("osidb", "PsProduct")
    PsProduct.objects.filter(team="middleware").update(label="middleware")
    PsProduct.objects.filter(short_name__in=LEGACY_SERVICES_PRODUCTS).update(
        label="services"
    )


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0289_remove_legacy_bz_id_index"),
    ]

    operations = [
        migrations.AddField(
            model_name="psproduct",
            name="label",
            field=models.CharField(blank=True, default="", max_length=50),
        ),
        migrations.RunPython(
            populate_labels,
            reverse_code=migrations.RunPython.noop,
            elidable=True,
        ),
    ]
