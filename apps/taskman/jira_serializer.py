"""
Jira entities serializers

This is a Jira simplified entity used to map in API
documentation the fields used by Taskman and its clients.

For an extensive list of Jira entity check the following
endpoint in your Jira instance:
/rest/api/2/field
(e.g. https://issues.stage.redhat.com/rest/api/2/field)
"""
from rest_framework import serializers


class JiraIssueTypeSerializer(serializers.Serializer):
    """
    Jira issue type, can be a Task, Story or Epic.
    """

    id = serializers.IntegerField()
    name = serializers.CharField()


class JiraUserSerializer(serializers.Serializer):
    name = serializers.CharField()
    key = serializers.CharField()
    emailAddress = serializers.CharField()
    displayName = serializers.CharField()


class JiraIssueFieldsSerializer(serializers.Serializer):
    issuetype = JiraIssueTypeSerializer()
    summary = serializers.CharField()
    description = serializers.CharField()
    assignee = JiraUserSerializer()
    customfield_12311140 = serializers.CharField(help_text="Task group key")


class JiraIssueSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    key = serializers.CharField()
    name = serializers.CharField()
    fields = JiraIssueFieldsSerializer()


class JiraIssueQueryResultSerializer(serializers.Serializer):
    total = serializers.IntegerField()
    issues = JiraIssueSerializer(many=True)


class JiraCommentSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    author = JiraUserSerializer()
    body = serializers.CharField()
    created = serializers.DateTimeField()
    updated = serializers.DateTimeField()
