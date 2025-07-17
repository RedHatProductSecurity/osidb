from django.db import models

from .constants import SYNC_TO_BZ


class BugzillaSyncMixin(models.Model):
    """
    mixin for syncing the model to the Bugzilla

    the sync between Bugzilla and the internal DB is done in a way
    that the model is first stored to the Bugzilla and then fetched
    back from there to make sure that the timestaps are kept in sync
    (otherwise there might be a few seconds differences)

    this mixin does not directly call Model.save
    because it is done when fetched from Bugzilla
    """

    class Meta:
        abstract = True

    def save(self, *args, bz_api_key=None, force_synchronous_sync=False, **kwargs):
        """
        save the model and sync it to Bugzilla

        when no Bugzilla API key is provided it is considered to be a call
        done by a collector or test and thus we perform just regular save

        Bugzilla sync is also conditional based on environment variable
        """
        # complete the save before the sync
        super().save(*args, **kwargs)

        # check BBSync conditions are met
        # and eventually perform the sync
        if SYNC_TO_BZ and bz_api_key is not None:
            self.bzsync(
                *args,
                bz_api_key=bz_api_key,
                force_synchronous_sync=force_synchronous_sync,
                **kwargs,
            )

    def bzsync(self, *args, bz_api_key, **kwargs):
        """
        Bugzilla sync of a specific class instance
        """
        raise NotImplementedError(
            "Inheritants of BugzillaSyncMixin must implement the bzsync method"
        )
