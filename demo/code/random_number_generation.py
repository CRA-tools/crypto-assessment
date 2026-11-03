import os


# Should not fire ECCG-DRBG-001/002/003/004/005: os.urandom does not identify a DRBG.
# PyCA has no public HMAC_DRBG, Hash_DRBG or CTR_DRBG API for a source-scan example.
def random_bytes():
    return os.urandom(32)
