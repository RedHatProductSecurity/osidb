"""
Written manually on 2023-08-30

* Copy CVEv5Version to PackageVer and copy CVEv5PackageVersions to Package.
* Leave old CVEv5Version and CVEv5PackageVersions model instances unmodified.
* Add ACLs to new Package model instances.
"""

from django.core.exceptions import ObjectDoesNotExist
from django.db import migrations
from django.db.models import Prefetch
from itertools import islice

BATCH_SIZE = 1000


def generate_vers(apps):
    """
    Generate new PackageVer instances to bulk-create.
    Old CVEv5Version could exist for multiple packages (CVEv5PackageVersions).
    New PackageVer is connected only to one package (Package). Therefore,
    for each CVEv5Version, as many new PackageVer are generated as there are
    associated instances of CVEv5PackageVersions.
    """
    CVEv5Version = apps.get_model("osidb", "CVEv5Version")
    CVEv5PackageVersions = apps.get_model("osidb", "CVEv5PackageVersions")
    PackageVer = apps.get_model("osidb", "PackageVer")
    Package = apps.get_model("osidb", "Package")
    for old_ver in (
        CVEv5Version.objects.prefetch_related(
            Prefetch(
                "packageversions_set",
                queryset=CVEv5PackageVersions.objects.all().only("uuid"),
            )
        )
        .only("uuid", "version")
        .all()
        .iterator()
    ):
        for old_pkg in old_ver.packageversions_set.all().iterator():
            try:
                new_pkg = Package.objects.get(uuid=old_pkg.uuid)
            except ObjectDoesNotExist:
                # The migration doesn't run in isolation. Packages can change while it runs.
                # It's not expected to be a large number, hence non-batched creation.
                # Note that the parallel tasks run with the old bzimport that instantiates
                # the old models CVEv5PackageVersions and CVEv5Version. This is not a problem
                # w.r.t. data integrity because of the branch `if "fixed_in" not in self.flaw.meta_attr`
                # in generate_fixed_in() in query.py (it also contains a detailed explanation).

                try:
                    old_flaw = old_pkg.flaw
                except ObjectDoesNotExist:
                    # Dangling CVEv5PackageVersions objects may exist.
                    # Skip processing those.
                    # Again not a problem due to the explanation above.
                    continue

                new_pkg = Package.objects.create(
                    uuid=old_pkg.uuid,
                    flaw=old_flaw,
                    package=old_pkg.package,
                    acl_read=old_flaw.acl_read,
                    acl_write=old_flaw.acl_write,
                    created_dt=old_flaw.created_dt,
                    updated_dt=old_flaw.updated_dt,
                )

            new_ver = PackageVer(
                package=new_pkg,
                version=old_ver.version,
            )
            yield new_ver


def generate_pkgs(apps):
    """
    Generate new Package instances to bulk-create.
    UUIDs are set identical so that it's easy to look up related Package
    instances in generate_vers().
    """
    CVEv5PackageVersions = apps.get_model("osidb", "CVEv5PackageVersions")
    Package = apps.get_model("osidb", "Package")
    for old_obj in CVEv5PackageVersions.objects.select_related("flaw").all().iterator():
        new_obj = Package(
            uuid=old_obj.uuid,
            flaw=old_obj.flaw,
            package=old_obj.package,
            acl_read=old_obj.flaw.acl_read,
            acl_write=old_obj.flaw.acl_write,
            created_dt=old_obj.flaw.created_dt,
            updated_dt=old_obj.flaw.updated_dt,
        )
        yield new_obj


def forwards_func(apps, schema_editor):
    """
    Copies data from old models to new models.
    """
    generator = generate_pkgs(apps)
    model = apps.get_model("osidb", "Package")
    while batch := list(islice(generator, BATCH_SIZE)):
        model.objects.bulk_create(batch, BATCH_SIZE)

    generator = generate_vers(apps)
    model = apps.get_model("osidb", "PackageVer")
    while batch := list(islice(generator, BATCH_SIZE)):
        model.objects.bulk_create(batch, BATCH_SIZE)


def backwards_func(apps, schema_editor):
    """
    Before this migration's forwards_func ran, the new models had no data.
    This migration didn't modify the old models.
    Therefore, reversal of the migration restores that state and deletes all the
    instances of the new models. The old data stays available in the old models
    (unless a future migration already deleted them). Data potentially fetched
    into the new models by bzimport in the meantime also get deleted by backwards_func.
    """
    PackageVer = apps.get_model("osidb", "PackageVer")
    Package = apps.get_model("osidb", "Package")

    PackageVer.objects.all().delete()
    Package.objects.all().delete()


class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0096_cvev5package__alerts"),
    ]

    operations = [
        migrations.RunPython(forwards_func, backwards_func, atomic=True),
    ]
