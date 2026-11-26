import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Should fire ECCG-DISK-003; XTS should not fire ECCG-DISK-001.
def xts_sector_encryption() -> None:
    key = os.urandom(64)
    tweak = (42).to_bytes(16, "little")
    sector = b"S" * 512
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(sector) + encryptor.finalize()
    decryptor = cipher.decryptor()
    recovered_plaintext = decryptor.update(ciphertext) + decryptor.finalize()


# Should fire ECCG-DISK-004 if the analyzer identifies CBC-ESSIV as a construction.
# Detecting its AES-CBC, AES-ECB and SHA-256 building blocks alone will not trigger that rule.
def cbc_essiv_sector_encryption() -> bytes:
    key = os.urandom(32)
    sector_number = (42).to_bytes(16, "little")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key)
    iv_key = digest.finalize()
    iv_cipher = Cipher(algorithms.AES(iv_key), modes.ECB())
    iv_encryptor = iv_cipher.encryptor()
    iv = iv_encryptor.update(sector_number) + iv_encryptor.finalize()
    sector_cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    sector_encryptor = sector_cipher.encryptor()
    return sector_encryptor.update(b"S" * 512) + sector_encryptor.finalize()


# Should fire ECCG-DISK-001; ordinary CBC does not establish CBC-ESSIV.
def cbc_sector_context() -> None:
    cipher = Cipher(algorithms.AES(os.urandom(32)), modes.CBC(os.urandom(16)))
    sector = b"S" * 512
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(sector) + encryptor.finalize()
    decryptor = cipher.decryptor()
    recovered_plaintext = decryptor.update(ciphertext) + decryptor.finalize()


# Should fire ECCG-DISK-002 when ChaCha20 is recorded as a stream-cipher primitive.
def stream_cipher_context() -> None:
    cipher = Cipher(algorithms.ChaCha20(os.urandom(32), os.urandom(16)), mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(b"example sector") + encryptor.finalize()
    decryptor = cipher.decryptor()
    recovered_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
