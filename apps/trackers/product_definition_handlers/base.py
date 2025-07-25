from osidb.models import Affect, Impact, PsModule


class ProductDefinitionRules:
    def __init__(self) -> None:
        from .default_handler import DefaultHandler
        from .major_incident_handler import MajorIncidentHandler
        from .moderate_handler import ModerateHandler
        from .unacked_handler import UnackedHandler

        # top-down priority
        # the first applicable handler
        # makes the pre-selection
        self.handlers = [
            MajorIncidentHandler(),
            DefaultHandler(),
            ModerateHandler(),
            UnackedHandler(),
        ]

    def file_tracker_offers(
        self,
        affect: Affect,
        impact: Impact,
        ps_module: PsModule,
        exclude_existing_trackers=False,
    ):
        offers = {}

        active_ps_update_streams = ps_module.active_ps_update_streams.all()
        if exclude_existing_trackers:
            active_ps_update_streams = active_ps_update_streams.exclude(
                name__in=affect.trackers.values_list("ps_update_stream", flat=True)
            )

        # generate the initial offer without any pre-selection
        for stream in active_ps_update_streams:
            offers[stream.name] = {
                "ps_update_stream": stream.name,
                "selected": False,
                "acked": not bool(
                    ps_module.unacked_ps_update_stream.filter(name=stream.name)
                ),
                "eus": bool(ps_module.eus_ps_update_streams.filter(name=stream.name)),
                "aus": bool(ps_module.aus_ps_update_streams.filter(name=stream.name)),
            }

        for handler in self.handlers:
            if handler.is_applicable(affect, impact, ps_module):
                return handler.get_offer(affect, impact, ps_module, offers)
        # there should always probably always be an applicable handler
        # but if there is none we just return the the offer unchanged
        return offers


class ProductDefinitionHandler:
    @staticmethod
    def is_applicable(affect: Affect, impact: Impact, ps_module: PsModule) -> bool:
        """
        check whether the hanler is applicable to the given affect
        the caller is responsible for checking the applicability before getting the offer
        """
        raise NotImplementedError(
            "Inheritants of ProductDefinitionHandler must implement the is_applicable method"
        )

    def get_offer(self, affect: Affect, impact: Impact, ps_module: PsModule, offers):
        """
        pre-select the streams
        """
        raise NotImplementedError(
            "Inheritants of ProductDefinitionHandler must implement the get_offer method"
        )
