"""
SLA Framework
"""

from django.db.models import Model

from .models import SLAContext, SLAPolicy


def sla_classify(instance: Model) -> SLAContext:
    """
    Classifies the instance into the proper SLA context
    with the proper SLA instance assigned which is the one
    resulting in the earliest SLA end under the given context.

    Returns empty SLA context if the instance is not bound by SLA.
    """
    policies = SLAPolicy.objects.all()
    if not policies.exists():
        return SLAContext()
    return min(policy.context(instance) for policy in policies)
