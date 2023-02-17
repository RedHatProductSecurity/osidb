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

    def save(self, *args, bz_api_key=None, **kwargs):
        """
        save the model by storing to Bugzilla and fetching back

        when no Bugzilla API key is provided it is considered to be a call
        done by a collector or test and thus we perform just regular save

        Bugzilla sync is also conditional based on environment variable
        """
        # preliminary save to link and annotate and
        # to make sure the validations are performed
        super().save(*args, **kwargs)
        self = self.__class__.objects.get(pk=self.pk)

        # check BBSync conditions are met
        if SYNC_TO_BZ and bz_api_key is not None:
            self.bzsync(*args, bz_api_key=bz_api_key, **kwargs)

    def bzsync(self, *args, bz_api_key, **kwargs):
        """
        Bugzilla sync of a specific class instance
        """
        raise NotImplementedError(
            "Inheritants of BugzillaSyncMixin must implement the bzsync method"
        )
