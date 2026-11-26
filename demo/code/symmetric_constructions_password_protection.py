import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# Should fire ECCG-PWH-002 and ECCG-KDF-002 advisories; should not fire ECCG-PWH-001.
def pbkdf2_password_verification() -> None:
    salt = os.urandom(16)
    password = b"example password for scanner testing"
    verifier = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000
    ).derive(password)
    PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000
    ).verify(password, verifier)


# Should fire ECCG-PWH-003; this example uses 64 MiB, below the stated 2 GiB recommendation.
def argon2id_password_verification() -> None:
    salt = os.urandom(16)
    password = b"example password for scanner testing"
    verifier = Argon2id(
        salt=salt, length=32, iterations=1, lanes=4, memory_cost=64 * 1024
    ).derive(password)
    Argon2id(
        salt=salt, length=32, iterations=1, lanes=4, memory_cost=64 * 1024
    ).verify(password, verifier)


# Should fire ECCG-PWH-001 (medium) and ECCG-KDF-001 (critical).
def scrypt_password_verification() -> None:
    salt = os.urandom(16)
    password = b"example password for scanner testing"
    verifier = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password)
    Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).verify(password, verifier)
