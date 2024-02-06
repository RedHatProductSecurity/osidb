from django.db.models import Q
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from osidb.mixins import ACLMixin
from osidb.models import Affect, PsModule

from .product_definition_handlers.base import ProductDefinitionRules
from .serializer import FlawUUIDListSerializer, TrackerSuggestionSerializer


# TODO study
class TrackerFileSuggestionView(APIView):
    @extend_schema(
        request=FlawUUIDListSerializer,
        description="Given a list of flaws, generates a list of suggested trackers to file.",
        responses=TrackerSuggestionSerializer(many=True),
    )
    def post(self, request, *args, **kwargs):
        """
        Use product definition to suggest trackers that can be filled against a list of flaws.

        From the user's flaw provided list, this method will:
        - use only affected flaws that will be fixed or delegated
        - use only affects related to modules with active_ps_update_streams
        - remove any embargoed flaw/affects related to modules that does not contains the private_trackers_allowed flag

        This method will also considers specific rules from product definition
        (e.g. unacked streams rules, UBI speacial handling)
        """
        serializer = FlawUUIDListSerializer(data=request.data)

        if serializer.is_valid():
            flaw_uuids = serializer.validated_data["flaw_uuids"]

            active_modules = PsModule.objects.filter(
                active_ps_update_streams__isnull=False
            ).distinct()
            active_module_names = active_modules.values_list("name", flat=True)

            embargoed_acl = ACLMixin.get_embargoed_acl()
            exclude_private = active_modules.filter(
                private_trackers_allowed=False
            ).values_list("name", flat=True)

            selected_affects = Affect.objects.filter(flaw__uuid__in=flaw_uuids)
            affects = selected_affects.filter(
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution__in=[
                    Affect.AffectResolution.FIX,
                    Affect.AffectResolution.DELEGATED,
                ],
                ps_module__in=active_module_names,
            ).exclude(
                (Q(flaw__acl_read=embargoed_acl) | Q(acl_read=embargoed_acl))
                & Q(ps_module__in=exclude_private)
            )
            not_applicable = selected_affects.difference(affects)

            targets = {}
            for affect in affects:
                key = (affect.ps_module, affect.ps_component)
                impact = max(affect.impact, affect.flaw.impact)

                ps_module = active_modules.get(name=affect.ps_module)

                if (
                    key in targets
                    and targets[key].get("impact")
                    and targets[key]["impact"] >= impact
                ):
                    # component is already suggested for a higher impact flaw/affect -- no-op
                    continue

                offers = {}
                for stream in ps_module.active_ps_update_streams.all():
                    offers[stream.name] = {
                        "ps_update_stream": stream.name,
                        "selected": False,
                        "acked": False,
                        "aus": False,
                        "eus": False,
                    }
                # TODO study
                offers = ProductDefinitionRules().file_tracker_offers(
                    affect, impact, ps_module, offers
                )
                targets[key] = {
                    "affect": affect,
                    "ps_module": affect.ps_module,
                    "ps_component": affect.ps_component,
                    "streams": list(offers.values()),
                    "impact": impact,
                    "selected": False,  # each module is deselected by default
                }

            serializer = TrackerSuggestionSerializer(
                {
                    "modules_components": list(targets.values()),
                    "not_applicable": not_applicable,
                }
            )
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
