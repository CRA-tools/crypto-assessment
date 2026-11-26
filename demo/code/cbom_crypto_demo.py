import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Should fire ECCG-SEAS-002 and ECCG-SYM-ENC-004/005/006 advisories for AES-GCM.
def aes_gcm_encryption():
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, b"example message", b"example header")
    plaintext = cipher.decrypt(nonce, ciphertext, b"example header")
    return ciphertext, plaintext


# Should fire ECCG-HASH-002: SHA-256 is below the 384-bit hash threshold.
# HMAC should also fire ECCG-MAC-002 and ECCG-HMAC-001 advisories.
def hmac_sha256_authentication():
    mac = hmac.HMAC(os.urandom(32), hashes.SHA256())
    mac.update(b"example message")
    return mac.finalize()


# Should fire ECCG-KEE-002 and ECCG-ECDLOG-002 for ECDH over P-256.
# HKDF should not fire ECCG-KDF-001, but may fire the ECCG-PWH-001 review finding.
def ecdh_hkdf_key_derivation():
    alice_private_key = ec.generate_private_key(ec.SECP256R1())
    bob_private_key = ec.generate_private_key(ec.SECP256R1())
    shared_secret = alice_private_key.exchange(ec.ECDH(), bob_private_key.public_key())
    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=os.urandom(32),
        info=b"example ECDH-derived key",
    ).derive(shared_secret)
    return derived_key
