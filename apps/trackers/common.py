"""
common tracker functionality shared between BTSs
"""
from functools import cached_property

from osidb.models import PsModule, PsUpdateStream


class TrackerQueryBuilder:
    """
    common base for the shared query building functionality
    """

    @property
    def tracker(self):
        """
        concrete name shortcut
        """
        return self.instance

    @cached_property
    def ps_module(self):
        """
        cached PS module getter
        """
        # even when multiple affects they must all have the same PS module
        return PsModule.objects.get(name=self.tracker.affects.first().ps_module)

    @cached_property
    def ps_component(self):
        """
        cached PS component getter
        """
        # even when multiple affects they must all have the same PS component
        return self.tracker.affects.first().ps_component

    @cached_property
    def ps_update_stream(self):
        """
        cached PS update stream getter
        """
        return PsUpdateStream.objects.get(name=self.tracker.ps_update_stream)
