import os

from cryptography.hazmat.primitives import cmac, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.poly1305 import Poly1305


# Should fire ECCG-MAC-002 and ECCG-HMAC-001 through 2030; ECCG-MAC-001 after expiry.
def hmac_sha1_example():
    key = b"K" * 16

    mac = hmac.HMAC(
        key=key,
        algorithm=hashes.SHA1(),
    )

    mac.update(b"message authenticated with HMAC-SHA1")

    tag = mac.finalize()
    return tag


# HMAC/CMAC should fire ECCG-MAC-002; Poly1305 should fire ECCG-MAC-001 if classified as MAC.
def mac_verification_examples() -> None:
    import os

    message = b"example authentication"
    hmac_key = os.urandom(32)
    hmac_context = hmac.HMAC(hmac_key, hashes.SHA256())
    hmac_context.update(message)
    hmac_tag = hmac_context.finalize()
    hmac_verifier = hmac.HMAC(hmac_key, hashes.SHA256())
    hmac_verifier.update(message)
    hmac_verifier.verify(hmac_tag)

    cmac_key = os.urandom(32)
    cmac_context = cmac.CMAC(algorithms.AES(cmac_key))
    cmac_context.update(message)
    cmac_tag = cmac_context.finalize()
    cmac_verifier = cmac.CMAC(algorithms.AES(cmac_key))
    cmac_verifier.update(message)
    cmac_verifier.verify(cmac_tag)

    one_time_key = os.urandom(32)
    poly1305_tag = Poly1305.generate_tag(one_time_key, message)
    Poly1305.verify_tag(one_time_key, message, poly1305_tag)


# Should fire ECCG-CBC-MAC-001 and ECCG-MAC-002 if recorded as CBC-MAC.
# A scanner may only recognize AES-CBC. This snippet authenticates fixed 32-byte messages.
def fixed_length_cbc_mac() -> bytes:
    key = os.urandom(32)
    message = b"M" * 32
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(16)))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return ciphertext[-16:]


# Should fire ECCG-GMAC-001/002/003 if recorded as GMAC with primitive mac.
# GCM with empty plaintext authenticates only the associated data; a scanner may report AE instead.
def gmac_authentication() -> bytes:
    key = AESGCM.generate_key(bit_length=256)
    nonce = (1).to_bytes(12, "big")
    cipher = AESGCM(key)
    return cipher.encrypt(nonce, b"", b"authenticated message")
