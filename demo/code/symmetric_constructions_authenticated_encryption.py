from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM, ChaCha20Poly1305


AES_KEY = b"A" * 16      # AES-128
HMAC_KEY = b"H" * 32     # HMAC key
IV = b"I" * 16           # CBC IV, fixed here only for deterministic test code


# Padding helper for the CBC/MAC composition snippets below.
def pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


# Should fire ECCG-MAC-002 and ECCG-HMAC-001 advisories.
def hmac_sha256(data: bytes) -> bytes:
    mac = hmac.HMAC(HMAC_KEY, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


# Should fire ECCG-SYM-ENC-003; the fixed IV is deliberately unsuitable for repeated use.
def aes_cbc_encrypt(data: bytes) -> bytes:
    cipher = Cipher(
        algorithms.AES(AES_KEY),
        modes.CBC(IV),
    )

    encryptor = cipher.encryptor()
    padded = pkcs7_pad(data)

    return encryptor.update(padded) + encryptor.finalize()


# May fire ECCG-MAC-001 (warning) if encryption/MAC occurrences are within 15 lines.
def mac_then_encrypt():
    plaintext = b"message protected with MAC-then-Encrypt"

    tag = hmac_sha256(plaintext)
    plaintext_and_tag = plaintext + tag

    ciphertext = aes_cbc_encrypt(plaintext_and_tag)

    return ciphertext


# May fire ECCG-MAC-001 (warning); source proximity cannot prove the composition order.
def encrypt_and_mac():
    plaintext = b"message protected with Encrypt-and-MAC"

    ciphertext = aes_cbc_encrypt(plaintext)
    tag = hmac_sha256(plaintext)

    return ciphertext, tag


# GCM/CCM should fire ECCG-SEAS-002; ChaCha20-Poly1305 should fire ECCG-SEAS-001.
def authenticated_encryption_examples() -> None:
    import os

    plaintext = b"example authenticated encryption"
    associated_data = b"example header"
    gcm_key = AESGCM.generate_key(bit_length=256)
    gcm = AESGCM(gcm_key)
    gcm_nonce = os.urandom(12)
    gcm_ciphertext = gcm.encrypt(gcm_nonce, plaintext, associated_data)
    gcm_plaintext = gcm.decrypt(gcm_nonce, gcm_ciphertext, associated_data)

    ccm_key = AESCCM.generate_key(bit_length=256)
    ccm = AESCCM(ccm_key, tag_length=16)
    ccm_nonce = os.urandom(13)
    ccm_ciphertext = ccm.encrypt(ccm_nonce, plaintext, associated_data)
    ccm_plaintext = ccm.decrypt(ccm_nonce, ccm_ciphertext, associated_data)

    chacha_key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(chacha_key)
    chacha_nonce = os.urandom(12)
    chacha_ciphertext = chacha.encrypt(chacha_nonce, plaintext, associated_data)
    chacha_plaintext = chacha.decrypt(chacha_nonce, chacha_ciphertext, associated_data)
