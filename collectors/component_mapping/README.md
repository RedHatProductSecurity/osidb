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
An omitted section clears all scopes; a stream omitted from this section has no
additional package restriction and follows the existing impact/tracker rules.
An explicitly empty list for a stream excludes every component. Invalid section
shapes roll back the entire sync transaction.

For streams present in product definitions, configured exclusions resolve to
AFFECTED/OOSS before module-dependent impact/tracker rules, even when the stream
has no associated module. Included components continue through those rules.
A missing stream, or a missing module without an explicit exclusion, leaves the
affect NEW for manual review.
ACE only applies automatic resolution after an affirmative OSV affected result.
Version-based NOTAFFECTED decisions take precedence, and missing or inconclusive
OSV data leaves the affect NEW for manual review even if scope excludes it.
ACE applies manual triage to any affect left NEW when labels are enabled,
regardless of stream.

Publish the complete upstream bundle and run the collector after deploying the
migration. Until that sync, normal resolution rules apply. Existing affects are
not rewritten when the data changes; correcting already-created affects is a
separate reviewed operation.
