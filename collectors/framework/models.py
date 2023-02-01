"""
collector framework models
"""
import logging
import re
from datetime import datetime
from functools import wraps
from typing import Dict, List, Optional, Type

import celery.states as celery_states
import inflection
from celery import Task, exceptions
from celery.schedules import crontab
from django.contrib.postgres import fields
from django.db import models
from django.utils import timezone
from psqlextra.fields import HStoreField

from config.celery import app
from config.settings import CELERY_BEAT_SCHEDULE
from osidb.mixins import NullStrFieldsMixin

from .constants import COLLECTOR_DRY_RUN, CRONTAB_PARAMS_NAMES

logger = logging.getLogger(__name__)


class CollectorFramework:
    """data collector management class"""

    @classmethod
    def collectors(cls) -> dict:
        """
        getter of all collector metadata objects
        returns dict where keys are the collector names
        """
        return {
            collector_metadata.name: collector_metadata
            for collector_metadata in CollectorMetadata.objects.all()
        }

    @classmethod
    def is_blocked(cls, collector_obj) -> bool:
        """collector block relation check"""
        collectors = cls.collectors()
        for dep_name in collector_obj.metadata.depends_on:
            dep = collectors.get(dep_name)

            if dep is None:
                raise RuntimeError(
                    f"Collector {collector_obj.name} error: "
                    f"Dependent collector {dep_name} does not exist"
                )

            if not dep.is_complete:
                return True

        return False

    @classmethod
    def reset(cls, collector_name) -> None:
        """
        reset RUNNING collector to READY state

        this is neccessary to be performed at every application start
        as if there were any running collectors in the moment of shutdown
        they are still recorded as running which is no more true
        other states can be preserved no problem
        """
        collector_metadata = cls.collectors().get(collector_name)
        if (
            collector_metadata
            and collector_metadata.is_running
            and collector_metadata.is_due
        ):
            collector_metadata.collector_state = CollectorMetadata.CollectorState.READY
            collector_metadata.save()


class CollectorMetadata(NullStrFieldsMixin):
    """
    persistent collector metadata

    the objects of this class should be always updated through their corresponding collectors only
    otherwise the stored collector metadata would desync with their DB counterpart
    """

    # unique name of associated collector
    name = models.CharField(editable=False, max_length=200, primary_key=True)
    # collector data model class names
    # model = models.CharField(blank=True, max_length=100, null=True)
    data_models = fields.ArrayField(
        models.CharField(max_length=100), default=list, null=True
    )

    # collector-specific metadata
    meta_attr = HStoreField(blank=True, null=True)

    def __str__(self):
        return self.name

    #################
    # DATA METADATA #
    #################

    class DataState(models.TextChoices):
        """
        allowable collected data completeness states

        as we are collecting the data we should follow the following diagram as
        initially we have nothing but when we eventually have something we cannot
        have nothing again and once we have everything we cannot miss something again
        we are not loosing any data and they can only become out-dated not incomplete

        EMPTY ---> PARTIAL ---> COMPLETE
        """

        EMPTY = "EMPTY"
        # PARTIAL value may make no sense if collector fetches all data in one batch
        # but if it does not it would mean that the initial data sync has not finished
        PARTIAL = "PARTIAL"
        COMPLETE = "COMPLETE"

    # state of the collected data completeness
    # it is set EMPTY by default as we assume that
    # when there is no collector metadata item
    # there are also no corresponding data
    data_state = models.CharField(
        default=DataState.EMPTY,
        choices=DataState.choices,
        max_length=10,
    )
    # a moment in history in which the current data would be complete and up-to-date
    # the same data does not have to be neither complete nor up-to-date in any later moment
    # once it is set the value should be only updated with a more recent one
    # as it makes no sense to outdate the data which were already up-to-date
    # complete data should always have this time stamp set
    updated_until_dt = models.DateTimeField(blank=True, null=True)

    @property
    def is_complete(self) -> bool:
        """completeness check"""
        return self.data_state == CollectorMetadata.DataState.COMPLETE

    ######################
    # COLLECTOR METADATA #
    ######################

    class CollectorState(models.TextChoices):
        """
        allowable collector processing states

        uses different logic than what is the default in celery

        PENDING : initial state of every collector
                  waiting for execution (according to celery)
        BLOCKED : collector is waiting for another one to complete its data
                  we assume that once complete the data cannot be incomplete again
        READY   : collector is ready to run but not currently running
        RUNNING : collector is just performing run

        PENDING ---> BLOCKED ---> READY ---> RUNNING
                                    ^           │
                                    ┕-----------┙

        the diagram is simplyfied as we do not set states if they would change immediately
        in case of PENDING we skip setting BLOCKED if not blocked and READY if we are about to run
        """

        PENDING = celery_states.PENDING
        BLOCKED = "BLOCKED"
        READY = "READY"
        RUNNING = "RUNNING"

    # collector state
    # different from collector (meta)data state as it describes the collector and not the data
    # different from celery Task state as the behavior is a bit modified
    collector_state = models.CharField(
        default=CollectorState.PENDING,
        choices=CollectorState.choices,
        max_length=10,
    )

    # celery crontab specifying when the collector should run
    # textual representation is stored - can be parsed back to crontab
    crontab = models.CharField(blank=True, max_length=100)

    # collector error
    # empty if the last run was smooth and raised exception otherwise
    # in the case of multiple exceptions (concurrency) there is any of them
    error = models.TextField(blank=True)

    # list of collector names on which this one depends on
    # it will refuse to start collecting until the data of all of these
    # are in complete state only proceeding to the BLOCKED state
    depends_on = fields.ArrayField(
        models.CharField(max_length=200), blank=True, default=list, null=True
    )

    @property
    def crontab_params(self) -> Optional[Dict[str, str]]:
        if self.crontab:
            params = re.search(r"<crontab: (.*) \(m/h/d/dM/MY\)>", self.crontab).group(
                1
            )
            return {
                param_name: param
                for param_name, param in zip(CRONTAB_PARAMS_NAMES, params.split())
            }

    @property
    def is_running(self) -> bool:
        """ongoing run check"""
        return self.collector_state == CollectorMetadata.CollectorState.RUNNING

    # track when was the last time the collector ran
    last_run_dt = models.DateTimeField(null=True)

    @property
    def is_due(self) -> bool:
        """Determines whether the collector is currently due for another run"""
        if self.crontab and self.last_run_dt:
            return crontab(**self.crontab_params).is_due(self.last_run_dt)[0]
        return True


class Collector(Task):
    """data collector base class"""

    # collector crontab schedule
    # defined in @collector decorator
    crontab = None

    # collector metadata
    # holds the all the collector metadata
    # is persistent between application runs
    # and enable inter-process access
    metadata = None

    # central point of setting collector dry run mode
    # it influences the behavior of collector save method
    # which either saves or only logs the collected data
    dry_run = None

    # collectors on which this collector depends on
    depends_on = None

    # collected data classes
    data_models = None

    ###########################
    # INSTANCE IDENTIFICATION #
    ###########################

    @staticmethod
    def get_name_from_entity(entity) -> str:
        """
        get name from given entity according to celery convention
        """
        return ".".join(
            [
                entity.__module__,
                inflection.underscore(entity.__name__),
            ]
        )

    @classmethod
    def get_name(cls) -> str:
        """
        get unique collector name
        defined on class level as we need it before the instantiation
        and collectors are singletons anyway
        """
        return cls.get_name_from_entity(cls)

    def gen_task_name(self, name, module) -> str:
        """
        celery task name generator
        we need to overwrite it as the default one gets confused
        with our decorator and thinks it is the task itself
        """
        return self.__class__.get_name()

    @property
    def name(self) -> str:
        """name getter shortcut"""
        return self.__class__.get_name()

    #####################
    # INSTANCE CREATION #
    #####################

    def __init__(self):
        """initiate collector"""
        # load the stored collector metadata or create new if not stored
        self.metadata, _ = CollectorMetadata.objects.get_or_create(
            name=self.name,
            defaults={
                "crontab": str(self.crontab) if self.crontab is not None else "",
                "depends_on": self.depends_on or [],
                "data_models": [data_model.__name__ for data_model in self.data_models]
                if self.data_models is not None
                else [],
            },
        )

        # set dry run status
        # local precedes global
        if self.dry_run is None:
            self.dry_run = COLLECTOR_DRY_RUN

    ######################
    # RUNTIME PROPERTIES #
    ######################

    @property
    def is_blocked(self) -> bool:
        """block check"""
        return CollectorFramework.is_blocked(self)

    @property
    def is_complete(self) -> bool:
        """data completeness check"""
        return self.metadata.is_complete

    @property
    def is_running(self) -> bool:
        """ongoing run check"""
        return self.metadata.is_running

    @property
    def is_up2date(self) -> bool:
        """
        data up-to-date check

        we suppose that in the case of failure the updated_until_dt is unchanged
        so we estimate the freshness based on it and the estimated next run
        and compare it with the current time to see whether

        updated_until_dt < remaining_estimate < now

        holds with the second delta being greater then the first which we consider outdated mark
        the idea is that if fresh the data should not be older then twice their refresh period
        as we expect that the refresh period is always less then or equal to collector run time

        incomplete data are always outdated
        we also suppose that complete data always have a updated_until_dt set

        the result is an estimation as with the crontab the runs
        do not have to be performed with a constant period
        """
        if not self.is_complete:
            return False

        last_run = self.metadata.updated_until_dt
        double_period = self.crontab.remaining_estimate(last_run) * 2

        if last_run + double_period < timezone.now():
            return False

        return True

    @property
    def has_failed(self) -> bool:
        """error check"""
        return bool(self.metadata.error)

    ########################
    # PERSISTANCE HANDLING #
    ########################

    def save(self, data):
        """
        generic save method for collected data
        it serves as a single point for general actions

            * logging collector result
            * running in dry run mode

        the data must itself provide save method
        and be convertable to string
        """
        if self.dry_run:
            logger.info(
                f"Skipping the save of the following data (running in dry run mode): {str(data)}"
            )

        else:
            logger.info(f"Performing the save of the following data: {str(data)}")
            data.save()
            # TODO
            # store non-critical errors during the save (eg. tracker cannot be linked to flaw)
            # - critical errors should be of course raised as exceptions
            # but we need some general clever way of storing collector errors
            # maybe we could use the celery task Django models for this
            # - the data could optionally provide .errors() method

    def store(self, complete=True, updated_until_dt=None, meta_attr=None) -> None:
        """
        store updated persistent collector metadata

        we follow the expected DataState process and refuse to change it otherwise
        and we also refuse to set the updated_until_dt to the past from the current value

        violating these constrains probably means a flaw in the collector design
        """
        if self.is_complete and not complete:
            raise RuntimeError(
                f"Collector {self.name} error: Once complete the data cannot be set incomplete"
            )

        if self.metadata.updated_until_dt is not None and (
            updated_until_dt is None
            or updated_until_dt < self.metadata.updated_until_dt
        ):
            raise RuntimeError(
                f"Collector {self.name} error: Data cannot be set less up-to-date"
            )

        self.metadata.data_state = (
            CollectorMetadata.DataState.PARTIAL
            if not complete
            else CollectorMetadata.DataState.COMPLETE
        ).value
        self.metadata.updated_until_dt = updated_until_dt
        self.metadata.meta_attr = meta_attr
        self.metadata.save()

    ###############
    # EXECEPTIONS #
    ###############

    class CollectorRunning(exceptions.Retry):
        """
        exception raised when this collector is already running
        to prevent duplicit run before the previous one finished
        """

        pass

    class CollectorBlocked(exceptions.Retry):
        """
        exception raised when this collector is blocked by unsatisfied dependencies
        to prevent undefined behavior with some required data not yet collected
        """

        pass

    #######################
    # EXECUTION FRAMEWORK #
    #######################

    def before_start(self, task_id, args, kwargs) -> None:
        """before run checks and actions"""
        # TODO from here until we set the state to RUNNING
        # it should ideally be a critical section concurrency-wise
        # so we should use some kind of lock
        #
        # as it seems non-trivial in celery I am not going to do it now
        # as with reasonable Collector period the race should be rare
        # and there should be a single collector instance in celery anyway
        # but let us keep it in mind as it can lead to something weird
        # TODO: use celery-singleton like in SDEngine
        #  just add base=Singleton to app.task() decorator

        # make sure we have fresh metadata first
        self.metadata.refresh_from_db()

        # check whether not already running
        if self.is_running:
            msg = f"Collector {self.name} run skipped: Collector is already running"
            logger.info(msg)
            raise Collector.CollectorRunning(msg)

        # check whether we should wait
        if self.is_blocked:
            self.metadata.collector_state = CollectorMetadata.CollectorState.BLOCKED
            self.metadata.save()
            msg = f"Collector {self.name} run skipped: Dependent collector data are not complete"
            logger.info(msg)
            raise Collector.CollectorBlocked(msg)

        # before run actions
        logger.info(f"Collector {self.name} run initiated")
        self.metadata.collector_state = CollectorMetadata.CollectorState.RUNNING
        self.metadata.last_run_dt = datetime.now()
        self.metadata.save()

    def on_success(self, retval, task_id, args, kwargs) -> None:
        """success handler"""
        logger.info(f"Collector {self.name} run completed")
        self.metadata.error = ""

    def on_failure(self, exc, task_id, args, kwargs, einfo) -> None:
        """error handler"""
        logger.info(f"Collector {self.name} run failed: {exc}")
        self.metadata.error = str(exc)

    def after_return(self, status, retval, task_id, args, kwargs, einfo) -> None:
        """general after run handler"""

        # Collector task was terminated because other instance of it is
        # already running, don't set the state to READY
        if isinstance(retval, Collector.CollectorRunning):
            return

        self.metadata.collector_state = CollectorMetadata.CollectorState.READY
        self.metadata.save()


def collector(
    base: Type[Collector] = Collector,
    crontab: Optional[crontab] = None,
    data_models: Optional[List[Type[models.Model]]] = None,
    depends_on: Optional[List[str]] = None,
    dry_run: Optional[bool] = None,
):
    """
    collector definition decorator

    base        - base class
    crontab     - crontab schedule - MANDATORY
    data_models - collected data classes
                  may be left None
    depends_on  - other collectors on which the collector
                  depends on, may be left None
    dry_run     - determines whether the collector saves the
                  data or just logs them, may be left None
    """

    def wrapper(func):
        if crontab is None:
            raise RuntimeError("Collector crontab must be defined")

        # reset collector state in case it was shutdown while running
        name = Collector.get_name_from_entity(func)
        # TODO this probably does not work
        # due to being run in separate containers
        CollectorFramework.reset(name)

        # register collector to celery beat
        CELERY_BEAT_SCHEDULE[name] = {
            "task": name,
            "schedule": crontab,
        }

        # register collector as task to celery app
        @app.task(
            base=base,
            bind=True,  # to get self
            crontab=crontab,
            data_models=data_models,
            depends_on=depends_on,
            dry_run=dry_run,
        )
        # wraps is necessary to set the correct collector name
        # which should correspond to collector module and fuction name
        # but would be substituted with inner function below otherwise
        @wraps(func)
        def inner(*args, **kwargs):
            return func(*args, **kwargs)

        return inner

    return wrapper
