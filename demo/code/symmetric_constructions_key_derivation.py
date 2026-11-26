import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash, ConcatKDFHMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF


# Agreed KDFs should not fire ECCG-KDF-001; ECCG-PWH-001 may request password-context review.
def key_derivation_examples() -> None:
    key_material = os.urandom(32)
    salt = os.urandom(32)
    hkdf_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"demo HKDF"
    ).derive(key_material)
    HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"demo HKDF"
    ).verify(key_material, hkdf_key)

    x963_key = X963KDF(
        algorithm=hashes.SHA256(), length=32, sharedinfo=b"demo X9.63"
    ).derive(key_material)
    X963KDF(
        algorithm=hashes.SHA256(), length=32, sharedinfo=b"demo X9.63"
    ).verify(key_material, x963_key)

    concat_hash_key = ConcatKDFHash(
        algorithm=hashes.SHA256(), length=32, otherinfo=b"demo SP800-56A"
    ).derive(key_material)
    ConcatKDFHash(
        algorithm=hashes.SHA256(), length=32, otherinfo=b"demo SP800-56A"
    ).verify(key_material, concat_hash_key)

    concat_hmac_key = ConcatKDFHMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, otherinfo=b"demo concat HMAC"
    ).derive(key_material)
    ConcatKDFHMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, otherinfo=b"demo concat HMAC"
    ).verify(key_material, concat_hmac_key)
