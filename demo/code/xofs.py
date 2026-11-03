from cryptography.hazmat.primitives import hashes

# ECCG-XOF-001's rejection branch has no native example: PyCA's SHAKE APIs are agreed.


# Should fire ECCG-XOF-002 if parameterSetIdentifier is 128; should not fire ECCG-XOF-001.
def shake128_short_output():
    digest = hashes.Hash(hashes.SHAKE128(16))
    digest.update(b"Example input for SHAKE128")
    return digest.finalize()


# Should fire ECCG-XOF-002 if the 128-bit output is recorded; a recorded value of 256 will not.
def shake256_short_output():
    digest = hashes.Hash(hashes.SHAKE256(16))
    digest.update(b"Example input for SHAKE256")
    return digest.finalize()


# Should not fire ECCG-XOF-001/002 when SHAKE256 is recorded with at least 256 bits.
def shake256_long_output():
    digest = hashes.Hash(hashes.SHAKE256(64))
    digest.update(b"Example input for SHAKE256")
    return digest.finalize()
