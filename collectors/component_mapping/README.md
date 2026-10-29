# Component Mapping Collector

Fetches the `component_mapping.json` from the `source-component-mapping` repository and syncs it into database models.

ACE uses this data as a pre-filter before searching lib-newtopia, blocking non-RH packages, resolving component names, and guarding against cross-ecosystem ambiguity.

The optional `package_scope` section maps update stream names to exhaustive
component inclusion lists, for example:

```json
{"package_scope": {"rhel-6-els": ["openssl", "krb5", "krb5-libs"]}}
```

The example is abbreviated. The data source owns list curation and any
release-specific source/binary expansion. OSIDB imports the supplied names into
`PackageScope`, normalizing case and removing duplicate components without
inferring aliases or package families.

Like the other reference lists, every successful sync replaces the scope data.
An omitted section clears all scopes; an absent stream has no additional
package restriction and follows the existing impact/tracker rules. An explicitly
empty list for a stream excludes every component. Invalid section shapes roll
back the entire sync transaction.

For configured streams, excluded components resolve to AFFECTED/OOSS before
impact/tracker rules; included components continue through those rules. A result
without a component stays NEW for manual review when its stream has a scope list.
Version-based NOTAFFECTED and unknown decisions take precedence. ACE applies
manual triage to any affect left NEW when labels are enabled, regardless of stream.

Publish the complete upstream bundle and run the collector after deploying the
migration. Until that sync, normal resolution rules apply. Existing affects are
not rewritten when the data changes; correcting already-created affects is a
separate reviewed operation.
