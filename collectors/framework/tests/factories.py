import factory
from celery.schedules import crontab
from pytz import UTC

from collectors.framework.models import CollectorMetadata
from osidb.dmodels import PsModule, PsProduct, PsUpdateStream
from osidb.models import Affect, Flaw, Tracker


class CollectorMetadataFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = CollectorMetadata

    name = factory.sequence(lambda n: f"task_{n}")
    data_models = factory.Faker(
        "random_choices",
        elements=[Affect, Flaw, PsModule, PsUpdateStream, PsProduct, Tracker],
    )
    meta_attr = {"test": "1"}
    data_state = factory.Faker(
        "random_element", elements=list(CollectorMetadata.DataState)
    )
    updated_until_dt = factory.Faker("date_time", tzinfo=UTC)
    collector_state = data_state = factory.Faker(
        "random_element", elements=list(CollectorMetadata.CollectorState)
    )
    crontab = str(crontab())
    last_run_dt = factory.Faker(
        "date_time_between",
        tzinfo=UTC,
        start_date=factory.SelfAttribute("..updated_until_dt"),
    )
