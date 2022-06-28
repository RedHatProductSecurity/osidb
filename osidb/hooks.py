"""
Custom hooks for drf-spectacular
"""


def response_metadata_postprocess_hook(result, generator, **kwargs):
    # this is a postprocess hook called by drf-spectacular after every schema
    # generation, we use it to add definitions for the global response metadata
    # that are added as part of every response by the ResponseMetadata
    # middleware
    DatetimeType = {"type": "string", "format": "date-time"}
    StringType = {"type": "string"}

    for path in result.get("paths", {}).values():
        for operation in path.values():
            for response in operation.get("responses", {}).values():
                # we must copy the schema due to the way that drf-spectacular
                # generates some of them (multiple references to the same obj)
                schema = (
                    response.get("content", {})
                    .get("application/json", {})
                    .get("schema", {})
                ).copy()

                props = schema.get("properties", {})
                props["dt"] = DatetimeType
                props["revision"] = StringType
                props["version"] = StringType
                props["env"] = StringType

                # sort by key (default drf-spectacular behavior)
                props = dict(sorted(props.items()))

                if ref := schema.pop("$ref", False):
                    # if this path points to a component reference for its
                    # schema then we need to use the `allOf` construct
                    # which will combine the fields of all objects within
                    # it, we cannot directly modify the component schema
                    # because then views that display list of components
                    # (e.g. /flaws) would have the meta fields for both
                    # the main response and for each flaw, which makes no sense
                    schema["allOf"] = [
                        {"$ref": ref},
                        {"type": "object", "properties": props},
                    ]
                else:
                    schema["properties"] = props

                # finally re-assign the copied schema so as to not pollute
                # other schemas for different content-types that might
                # share the same dict (due to aforementioned bug)
                response.get("content", {}).get("application/json", {})[
                    "schema"
                ] = schema

                # In general, drf-spectacular doesn't do much with APIView
                # and @api_view views, thus we do this "hack" to provide
                # them with the minimum information that is global to all
                # responses
                if "content" not in response:
                    # TODO: try to fix this in the view code itself,
                    # by using proper views + serializers as
                    # drf-spectacular does most of its introspection by
                    # querying each view's serializers
                    response["content"] = {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": props,
                            },
                        }
                    }
                    # response body is no longer empty, the del
                    # + assignment is to preserve order
                    del response["description"]
                    response["description"] = ""
    return result
