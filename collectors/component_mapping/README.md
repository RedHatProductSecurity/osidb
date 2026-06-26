# Component Mapping Collector

Fetches the `component_mapping.json` from the `source-component-mapping` repository and syncs it into database models.

ACE uses this data as a pre-filter before searching lib-newtopia, blocking non-RH packages, resolving component names, and guarding against cross-ecosystem ambiguity.
