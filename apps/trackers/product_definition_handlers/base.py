from osidb.models import Affect, Impact, PsUpdateStream


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

    def file_tracker_offer(
        self,
        affect: Affect,
        impact: Impact,
        ps_update_stream: PsUpdateStream,
        exclude_existing_trackers=False,
    ):
        # Only generate offers for active streams
        if not ps_update_stream.is_active:
            return None

        if (
            exclude_existing_trackers
            and affect.tracker is not None
            and affect.tracker.ps_update_stream == ps_update_stream.name
        ):
            # Stream already tracked
            return None

        # generate the initial offer without any pre-selection
        offer = {
            "ps_update_stream": ps_update_stream.name,
            "selected": False,
            "acked": not ps_update_stream.is_unacked,
            "eus": ps_update_stream.is_eus,
            "aus": ps_update_stream.is_aus,
        }

        for handler in self.handlers:
            if handler.is_applicable(affect, impact, ps_update_stream):
                return handler.get_offer(affect, impact, ps_update_stream, offer)
        # there should always probably always be an applicable handler
        # but if there is none we just return the the offer unchanged
        return offer


class ProductDefinitionHandler:
    @staticmethod
    def is_applicable(
        affect: Affect, impact: Impact, ps_update_stream: PsUpdateStream
    ) -> bool:
        """
        check whether the hanler is applicable to the given affect
        the caller is responsible for checking the applicability before getting the offer
        """
        raise NotImplementedError(
            "Inheritants of ProductDefinitionHandler must implement the is_applicable method"
        )

    def get_offer(
        self, affect: Affect, impact: Impact, ps_update_stream: PsUpdateStream, offers
    ):
        """
        pre-select the streams
        """
        raise NotImplementedError(
            "Inheritants of ProductDefinitionHandler must implement the get_offer method"
        )
