package cbom.eccg.oid_constants

# String placeholder for algorithms with no verified OID. Unlike null, this
# remains type-compatible with the string returned by get_component_oid_or_empty.
# The surrounding spaces are intentional: that getter trims strings, so neither
# missing OIDs nor input containing this placeholder can match it. Do not trim it
# or replace it with "", which would match components without an OID.
NO_OID := " NO_OID "
