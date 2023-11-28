import random


class WeightedReplicaRouter:
    def db_for_read(self, model, **hints):
        """
        Distributes reads between the read-only replica (2/3) and default (1/3).
        """
        choices = ["default", "read-replica-1"]
        weights = [0.3, 1]
        return random.choices(choices, cum_weights=weights)[0]  # nosec

    def db_for_write(self, model, **hints):
        """
        Writes always go to the default database.
        """
        return "default"

    def allow_relation(self, obj1, obj2, **hints):
        """
        Allow all relations as all other databases are assumed to be replicas.
        """
        return True

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Only allow migrations on default database as replicas are read-only.
        """
        return db == "default"
