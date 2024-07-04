from rest_framework.throttling import UserRateThrottle


class AffectUserRateThrottle(UserRateThrottle):
    """
    Custom throttling rate to use for the affects view since the bulk operations
    are not accessible through the bindings yet, so there may be lots
    of requests to update a flaw with many affects.
    """

    # TODO: When bulk operations are supported in the bindings, remove this class
    # so that the affects view uses the same rate as everything else
    rate = "600/min"
