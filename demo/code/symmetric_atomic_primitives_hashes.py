from cryptography.hazmat.primitives import hashes, hmac


# Should fire ECCG-HASH-001: SHA-224 is not an agreed hash.
def sha224_hmac():
    mac = hmac.HMAC(
        key=b"K" * 32,
        algorithm=hashes.SHA224(),
    )

    mac.update(b"message using SHA-224 inside HMAC")
    return mac.finalize()


# Should fire ECCG-HASH-001: SHA-512/224 is not an agreed hash.
def sha512_224_hmac():
    mac = hmac.HMAC(
        key=b"K" * 32,
        algorithm=hashes.SHA512_224(),
    )

    mac.update(b"message using SHA-512/224 inside HMAC")
    return mac.finalize()


# Should fire ECCG-HASH-001 if BLAKE2b is detected as a hash primitive.
def blake2b_digest():
    # External / non-ECCG hash (should likely be flagged by policy)
    blake2b_obj = hashes.Hash(hashes.BLAKE2b(64))
    blake2b_obj.update(b"data")
    digest_blake2b = blake2b_obj.finalize()

    return digest_blake2b


# Should fire ECCG-HASH-002: SHA-256 is agreed but below the 384-bit threshold.
def sha256_digest() -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b"example message")
    return digest.finalize()


# Should not fire ECCG-HASH-001/002: SHA-384 is agreed and meets the threshold.
def sha384_digest() -> bytes:
    digest = hashes.Hash(hashes.SHA384())
    digest.update(b"example message")
    return digest.finalize()
