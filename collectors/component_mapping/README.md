# Component Mapping Collector

Fetches the `component_mapping.json` from the `source-component-mapping` repository and syncs it into database models.

ACE uses this data as a pre-filter before searching lib-newtopia, blocking non-RH packages, resolving component names, and guarding against cross-ecosystem ambiguity.

The `rhel6_els_packages` section supplies the published RHEL 6 ELS inclusion
names and release-specific `source_package_aliases` (binary RPM -> SRPM).
The collector expands only published source-package families into
`Rhel6ElsPackage`. It does not use cross-release component mappings or suffix
heuristics. Older bundles without this section preserve the previous list;
an explicitly empty or malformed section fails the sync transaction rather
than clearing coverage. Before the first successful load, coverage is unknown.

Deploy the database migration and the bundle containing this section, then run
the component-mapping collector before enabling automatic RHEL 6 ELS resolution.
ACE keeps unknown coverage at NEW with a manual-triage label. Proven excluded
packages resolve to AFFECTED/OOSS; included packages retain the normal impact
and tracker rules. Version-based NOTAFFECTED/unknown decisions take precedence.
Existing affects are not rewritten; correcting already-created affects is a
separate reviewed operation.
