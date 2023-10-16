import factory

from apps.trackers.models import JiraProjectFields


class JiraProjectFieldsFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = JiraProjectFields

    project_key = factory.Faker("word")
    field_id = factory.Faker("word")
    field_name = factory.Faker("word")
    allowed_values = factory.List([{"name": factory.Faker("word")} for _ in range(3)])
