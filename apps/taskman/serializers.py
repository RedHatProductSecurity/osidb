from django.contrib.auth.models import User
from rest_framework import serializers

from apps.taskman.models import FlawTask, TaskOwner
from osidb.models import Flaw


class MinimalFlawSerializer(serializers.ModelSerializer):
    def validate(self, data):
        if not data.get("uuid", False) and not data.get("cve_id", False):
            raise serializers.ValidationError("Either uuid or cve_id must be provided")

    class Meta:
        model = Flaw
        fields = ("uuid", "cve_id")


class TaskOwnerSerializer(serializers.ModelSerializer):
    kerberos_user_id = serializers.CharField(source="user.username")
    bz_user_id = serializers.CharField(read_only=True)
    jira_user_id = serializers.CharField(read_only=True)

    def validate(self, data):
        krb5_id = data["kerberos_user_id"]
        try:
            User.objects.get(username=krb5_id)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                f"User with kerberos id {krb5_id} not found."
            )
        return data

    class Meta:
        model = TaskOwner
        fields = ("kerberos_user_id", "bz_user_id", "jira_user_id")


class FlawTaskSerializer(serializers.ModelSerializer):
    flaw = MinimalFlawSerializer()
    owner = TaskOwnerSerializer()

    def create(self, validated_data):
        flaw_data = validated_data.pop("flaw")
        flaw_pk = flaw_data.get("uuid", flaw_data["cve_id"])
        owner_data = validated_data.pop("owner")

    class Meta:
        model = FlawTask
        fields = ("owner", "flaw")
