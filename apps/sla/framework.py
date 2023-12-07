"""
SLA Framework
"""
import logging
from os.path import join
from typing import List

import yaml
from django.db.models import Model

from apps.workflows.helpers import singleton

from .constants import SLA_DEFINITION_FILE
from .exceptions import SLADefinitionError
from .models import SLAContext, SLAPolicy

logger = logging.getLogger(__name__)


@singleton
class SLAFramework:
    """
    SLA operating framework

    loads and provides all available SLA policies
    and implements all related operating logic
    """

    _policies = []
    _sla_definition_file = SLA_DEFINITION_FILE

    @property
    def policies(self) -> List[SLAPolicy]:
        """
        policies getter

        loads the policies on the first run
        """
        if not self._policies:
            self.load_policies()

        return self._policies

    def load_policies(self) -> None:
        """policies loader"""
        try:
            with open(
                file=join(self._sla_definition_file), mode="r", encoding="utf8"
            ) as stream:
                # create and register policy instances
                logger.info(
                    f"Processing policy definitions: {self._sla_definition_file}"
                )
                for policy in yaml.safe_load_all(stream):
                    self._policies.append(SLAPolicy(policy))

        except (KeyError, ValueError) as exception:
            raise SLADefinitionError(
                f"Invalid SLA policy definition: {self._sla_definition_file}"
            ) from exception

    def classify(self, instance: Model) -> SLAContext:
        """
        classify the instance into the proper SLA context
        with the proper SLA instance assigned which is the one
        resulting in the earliest SLA end under the given contex

        returns empty SLA context if the instance is not bound by SLA
        """
        return min(policy.context(instance) for policy in self.policies)
