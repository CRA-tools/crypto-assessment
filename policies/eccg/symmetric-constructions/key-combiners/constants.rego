package cbom.eccg.symmetric_constructions.key_combiners.constants

import data.cbom.eccg.oid_constants.NO_OID

#
# Source:
# - https://www.etsi.org/deliver/etsi_ts/103700_103799/103744/01.02.01_60/ts_103744v010201p.pdf
#
# CycloneDX primitive: combiner
# No dedicated CycloneDX algorithm family verified.
# ============================================================

CATKDF_KEY_COMBINER_SCHEME_NAMES := {
    "CatKDF",
    "CATKDF",
    "Cat-KDF",
    "Concatenate-KDF",
    "Concatenate-KeyCombiner",
    "Concatenate-Hybrid-KeyCombiner",
    "ETSI-CatKDF",
}

CATKDF_KEY_COMBINER_SCHEME_FAMILIES := set()

# No standalone CatKDF OID verified
CATKDF_KEY_COMBINER_SCHEME_OIDS := {
    "CatKDF": NO_OID,
    "CATKDF": NO_OID,
    "Cat-KDF": NO_OID,
    "Concatenate-KDF": NO_OID,
    "Concatenate-KeyCombiner": NO_OID,
    "Concatenate-Hybrid-KeyCombiner": NO_OID,
    "ETSI-CatKDF": NO_OID,
}

CATKDF_KEY_COMBINER_SCHEME_OID_VALUES := {
    oid | oid := CATKDF_KEY_COMBINER_SCHEME_OIDS[_]
}


#
# Source:
# - https://www.etsi.org/deliver/etsi_ts/103700_103799/103744/01.02.01_60/ts_103744v010201p.pdf
#
# CycloneDX primitive: combiner
# No dedicated CycloneDX algorithm family verified.
# ============================================================

CASKDF_KEY_COMBINER_SCHEME_NAMES := {
    "CasKDF",
    "CASKDF",
    "Cas-KDF",
    "Cascade-KDF",
    "Cascade-KeyCombiner",
    "Cascade-Hybrid-KeyCombiner",
    "ETSI-CasKDF",
}

CASKDF_KEY_COMBINER_SCHEME_FAMILIES := set()

# No standalone CasKDF OID verified
CASKDF_KEY_COMBINER_SCHEME_OIDS := {
    "CasKDF": NO_OID,
    "CASKDF": NO_OID,
    "Cas-KDF": NO_OID,
    "Cascade-KDF": NO_OID,
    "Cascade-KeyCombiner": NO_OID,
    "Cascade-Hybrid-KeyCombiner": NO_OID,
    "ETSI-CasKDF": NO_OID,
}

CASKDF_KEY_COMBINER_SCHEME_OID_VALUES := {
    oid | oid := CASKDF_KEY_COMBINER_SCHEME_OIDS[_]
}

