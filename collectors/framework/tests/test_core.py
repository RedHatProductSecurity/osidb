import pytest
from celery.schedules import crontab
from django.utils import timezone

from collectors.framework.models import CollectorMetadata, collector
from osidb.models import Affect, Flaw, Tracker

pytestmark = pytest.mark.unit

# NOTE: All testing collectors needs to have unique names because
# once the collector is defined in the test function scope and it
# remains registered even in the scope of other testing functions
# for the rest of the test run. Use name "test_collector<N>" where
# N is the next number in order starting from 0


class TestCollectorFramework:
    def test_create_collector(self):
        """test that collector metadata are correctly stored after initialization"""
        cron = crontab(
            minute="5", hour="12", day_of_week="3", day_of_month="11", month_of_year="7"
        )

        @collector(
            crontab=cron,
            data_models=[Affect, Flaw, Tracker],
            dry_run=True,
        )
        def test_collector0(collector_obj):
            return str(collector_obj.name)

        test_collector0()

        metadata = CollectorMetadata.objects.filter(
            name=f"{self.__module__}.test_collector0"
        ).first()
        assert metadata is not None
        assert metadata.crontab == str(cron)
        assert crontab(**metadata.crontab_params) == cron
        assert set(metadata.data_models) == {
            model.__name__ for model in [Affect, Flaw, Tracker]
        }
        assert metadata.data_state == CollectorMetadata.DataState.EMPTY
        assert metadata.updated_until_dt is None
        assert metadata.collector_state == CollectorMetadata.CollectorState.PENDING
        assert not metadata.error
        assert not metadata.depends_on

    def test_create_multiple_collectors(self):
        """test that multiple collectors don't interfere between themselves"""

        @collector(crontab=crontab(minute="1"), data_models=[Flaw])
        def test_collector1(collector_obj):
            return str(collector_obj.name)

        @collector(crontab=crontab(minute="2"), data_models=[Affect])
        def test_collector2(collector_obj):
            return str(collector_obj.name)

        @collector(crontab=crontab(minute="3"), data_models=[Tracker])
        def test_collector3(collector_obj):
            return str(collector_obj.name)

        test_collector2()
        test_collector3()
        test_collector1()

        for i, data_model in zip(range(1, 4), [Flaw, Affect, Tracker]):
            metadata = CollectorMetadata.objects.get(
                name=f"{self.__module__}.test_collector{i}"
            )
            assert metadata.crontab_params["minute"] == str(i)
            assert set(metadata.data_models) == {data_model.__name__}

    def test_mandatory_crontab(self):
        """test that collector must be defined with crontab"""
        with pytest.raises(RuntimeError) as exc_info:

            @collector()
            def test_collector4(collector_obj):
                return str(collector_obj.name)

        assert str(exc_info.value) == "Collector crontab must be defined"

    def test_collector_dependency(self):
        """
        test that collector with dependency won't start until the dependent
        collectors will finish the data collection
        """

        @collector(
            crontab=crontab(minute="5"),
            depends_on=[f"{self.__module__}.test_collector6"],
        )
        def test_collector5(collector_obj):
            collector_obj.store(updated_until_dt=timezone.now())
            return str(collector_obj.name)

        @collector(
            crontab=crontab(minute="5"),
        )
        def test_collector6(collector_obj):
            collector_obj.store(updated_until_dt=timezone.now())
            return str(collector_obj.name)

        test_collector5()
        test_collector6()

        collector6_metadata = CollectorMetadata.objects.get(
            name=f"{self.__module__}.test_collector6"
        )

        for incomplete_data_state in [
            CollectorMetadata.DataState.EMPTY,
            CollectorMetadata.DataState.PARTIAL,
        ]:
            collector6_metadata.data_state = incomplete_data_state
            collector6_metadata.save()

            assert test_collector5.apply().state == "RETRY"

        collector6_metadata.data_state = CollectorMetadata.DataState.COMPLETE
        collector6_metadata.save()

        test_collector5.apply().get()

    def test_only_one_collector_instance(self):
        @collector(
            crontab=crontab(minute="5"),
        )
        def test_collector7(collector_obj):
            collector_obj.store(updated_until_dt=timezone.now())
            return str(collector_obj.name)

        test_collector7()

        metadata = CollectorMetadata.objects.get(
            name=f"{self.__module__}.test_collector7"
        )
        metadata.collector_state = CollectorMetadata.CollectorState.RUNNING
        metadata.save()

        for _ in range(5):
            assert test_collector7.apply().state == "RETRY"
