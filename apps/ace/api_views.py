from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.ace.tasks import (
    AutoResolveInputError,
    PreFilterAction,
    SpecialWorkflow,
    _pre_filter_component,
    auto_resolve_affect_fields,
    pre_filter_result_to_dict,
)
from osidb.api_views import RudimentaryUserPathLoggingMixin
from osidb.models import Flaw, PsModule
from osidb.models.abstract import Impact

_AUTO_RESOLVE_IMPACTS = frozenset(
    {Impact.LOW, Impact.MODERATE, Impact.IMPORTANT, Impact.CRITICAL}
)


class ComponentMappingPreFilterResponseSerializer(serializers.Serializer):
    action = serializers.ChoiceField(
        choices=[action.value for action in PreFilterAction]
    )
    label = serializers.CharField()
    resolved_names = serializers.ListField(child=serializers.CharField())
    reason = serializers.CharField()
    workflow = serializers.ChoiceField(
        choices=[workflow.value for workflow in SpecialWorkflow]
    )


class AffectAutoResolveResponseSerializer(serializers.Serializer):
    affectedness = serializers.CharField()
    resolution = serializers.CharField()


class PsModuleActiveStreamsResponseSerializer(serializers.Serializer):
    ps_modules = serializers.DictField(
        child=serializers.ListField(child=serializers.CharField())
    )


@extend_schema(
    description=(
        "Evaluate ACE component-mapping pre-filter rules for a single flaw component. "
        "Used by the affect-creator microservice before querying lib-newtopia."
    ),
    parameters=[
        OpenApiParameter(
            name="component",
            type=str,
            location=OpenApiParameter.QUERY,
            required=True,
            description="Flaw component name to evaluate.",
        ),
        OpenApiParameter(
            name="ecosystem",
            type=str,
            location=OpenApiParameter.QUERY,
            required=False,
            description="Upstream ecosystem context (e.g. npm, pypi).",
        ),
        OpenApiParameter(
            name="flaw_components",
            type=str,
            location=OpenApiParameter.QUERY,
            required=False,
            description="Comma-separated list of all flaw components (for Go stdlib detection).",
        ),
    ],
    responses={200: ComponentMappingPreFilterResponseSerializer},
)
class ComponentMappingPreFilterView(RudimentaryUserPathLoggingMixin, APIView):
    """Run ACE pre-filter logic using component_mapping collector data."""

    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        component = request.query_params.get("component")
        if not component or not str(component).strip():
            return Response(
                {"component": ["This field is required."]},
                status=400,
            )

        ecosystem = request.query_params.get("ecosystem", "")
        flaw_components_raw = request.query_params.get("flaw_components", "")
        flaw_components = [
            part.strip() for part in flaw_components_raw.split(",") if part.strip()
        ]

        result = _pre_filter_component(flaw_components, component, ecosystem)
        return Response(pre_filter_result_to_dict(result))


@extend_schema(
    description=(
        "Return active PS update stream names for one or more PS modules. "
        "Used by affect-creator for Go stdlib Phase 4 builder-container affects."
    ),
    parameters=[
        OpenApiParameter(
            name="names",
            type=str,
            location=OpenApiParameter.QUERY,
            required=True,
            description="Comma-separated PS module names (e.g. openshift-4,cnv-4).",
        ),
    ],
    responses={200: PsModuleActiveStreamsResponseSerializer},
)
class PsModuleActiveStreamsView(RudimentaryUserPathLoggingMixin, APIView):
    """Expose PsModule.active_ps_update_streams for external ACE integrations."""

    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        names_raw = request.query_params.get("names", "")
        names = [part.strip() for part in names_raw.split(",") if part.strip()]
        if not names:
            return Response(
                {"names": ["This field is required."]},
                status=400,
            )

        ps_modules: dict[str, list[str]] = {}
        for name in names:
            try:
                ps_module = PsModule.objects.get(name=name)
            except PsModule.DoesNotExist:
                ps_modules[name] = []
                continue

            ps_modules[name] = list(
                ps_module.active_ps_update_streams.values_list("name", flat=True)
            )

        return Response({"ps_modules": ps_modules})


@extend_schema(
    description=(
        "Resolve ACE affectedness and resolution for a would-be affect using the "
        "same rules as Affect.auto_resolve(). Used by the affect-creator microservice."
    ),
    parameters=[
        OpenApiParameter(
            name="ps_update_stream",
            type=str,
            location=OpenApiParameter.QUERY,
            required=True,
            description="Target PS update stream for the affect.",
        ),
        OpenApiParameter(
            name="flaw",
            type=str,
            location=OpenApiParameter.QUERY,
            required=False,
            description="Flaw UUID (for impact fallback and CVSS-based defer rules).",
        ),
        OpenApiParameter(
            name="impact",
            type=str,
            location=OpenApiParameter.QUERY,
            required=False,
            description="Affect impact; defaults to the flaw impact when flaw is given.",
        ),
        OpenApiParameter(
            name="flaw_has_high_cvss_score",
            type=bool,
            location=OpenApiParameter.QUERY,
            required=False,
            description=(
                "Whether the flaw has CVSSv3 >= 7.0; computed from the flaw when omitted."
            ),
        ),
    ],
    responses={200: AffectAutoResolveResponseSerializer},
)
class AffectAutoResolveView(RudimentaryUserPathLoggingMixin, APIView):
    """Expose Affect.auto_resolve() for external ACE integrations."""

    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        ps_update_stream = request.query_params.get("ps_update_stream")
        if not ps_update_stream or not str(ps_update_stream).strip():
            return Response(
                {"ps_update_stream": ["This field is required."]},
                status=400,
            )

        flaw_uuid = request.query_params.get("flaw")
        flaw = None
        if flaw_uuid:
            try:
                flaw = Flaw.objects.get(uuid=flaw_uuid)
            except Flaw.DoesNotExist:
                return Response(
                    {"flaw": [f"Flaw '{flaw_uuid}' does not exist."]},
                    status=404,
                )

        impact = request.query_params.get("impact", "")
        if impact and impact not in _AUTO_RESOLVE_IMPACTS:
            return Response(
                {"impact": ["Unsupported impact value."]},
                status=400,
            )

        flaw_has_high_cvss_score = request.query_params.get("flaw_has_high_cvss_score")
        if flaw_has_high_cvss_score is not None:
            cvss_literal = flaw_has_high_cvss_score.lower()
            if cvss_literal == "true":
                flaw_has_high_cvss_score = True
            elif cvss_literal == "false":
                flaw_has_high_cvss_score = False
            else:
                return Response(
                    {"flaw_has_high_cvss_score": ["Must be 'true' or 'false'."]},
                    status=400,
                )

        try:
            result = auto_resolve_affect_fields(
                ps_update_stream=ps_update_stream,
                impact=impact,
                flaw=flaw,
                flaw_has_high_cvss_score=flaw_has_high_cvss_score,
            )
        except AutoResolveInputError as exc:
            return Response(exc.errors, status=400)
        return Response(result)
