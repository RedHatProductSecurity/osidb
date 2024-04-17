from osidb.models import Affect, Impact, PsModule


class ProductDefinitionRules:
    def __init__(self) -> None:
        from .fedramp_handler import FedrampHandler
        from .ubi_handler import UBIHandler
        from .unacked_handler import UnackedHandler

        # The order matters!
        self.handlers = [
            UnackedHandler(),
            UBIHandler(),
            FedrampHandler(),
        ]

    def file_tracker_offers(
        self, affect: Affect, impact: Impact, ps_module: PsModule, blank_offers
    ):
        for handler in self.handlers:
            blank_offers = handler.get_offer(affect, impact, ps_module, blank_offers)
        return blank_offers


class ProductDefinitionHandler:
    def get_offer(self, affect: Affect, impact: Impact, ps_module: PsModule, offers):
        raise NotImplementedError(
            "Inheritants of ProductDefinitionHandler must implement the get_offer method"
        )
