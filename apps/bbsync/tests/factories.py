import factory

from apps.bbsync.models import BugzillaComponent, BugzillaProduct


class BugzillaProductFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = BugzillaProduct

    name = factory.sequence(lambda n: f"bz_product{n}")


class BugzillaComponentFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = BugzillaComponent

    name = factory.sequence(lambda n: f"bz_component{n}")
    default_owner = factory.Faker(
        "random_element",
        elements=["contributor@fedora.org", "owner@redhat.com", "user@redhat.com"],
    )
    default_cc = factory.List(
        [
            f"email{i}@{domain}"
            for i in range(3)
            for domain in ["fedora.org", "redhat.com"]
        ]
    )

    product = factory.SubFactory(BugzillaProductFactory)
