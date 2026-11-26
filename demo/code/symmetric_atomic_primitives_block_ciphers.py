from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers import algorithms as legacy_algorithms


# Should fire ECCG-BLOCK-001: Blowfish is outside the agreed block-cipher list.
def blowfish_encryption():
    key = b"K" * 16      # Blowfish key
    iv = b"I" * 8        # Blowfish has a 64-bit block size

    cipher = Cipher(
        legacy_algorithms.Blowfish(key),
        modes.CBC(iv),
    )

    encryptor = cipher.encryptor()
    plaintext = b"A" * 16

    return encryptor.update(plaintext) + encryptor.finalize()


# Should fire ECCG-BLOCK-003; two-key 3DES should also fire ECCG-BLOCK-004.
def two_key_triple_des_encryption():
    key = b"1234567890ABCDEF"  # 16-byte / two-key TripleDES material
    iv = b"12345678"           # 3DES has a 64-bit block size

    cipher = Cipher(
        legacy_algorithms.TripleDES(key),
        modes.CBC(iv),
    )

    encryptor = cipher.encryptor()
    plaintext = b"B" * 16

    return encryptor.update(plaintext) + encryptor.finalize()


# AES-128 should fire ECCG-BLOCK-005; SM4 should fire ECCG-BLOCK-001; ECB fires ECCG-SYM-ENC-001.
def aes_and_sm4_examples() -> None:
    aes128_cipher = Cipher(algorithms.AES(b"A" * 16), modes.ECB())
    aes128_encryptor = aes128_cipher.encryptor()
    aes128_ciphertext = aes128_encryptor.update(b'P' * 16) + aes128_encryptor.finalize()
    aes256_cipher = Cipher(algorithms.AES(b"A" * 32), modes.ECB())
    aes256_encryptor = aes256_cipher.encryptor()
    aes256_ciphertext = aes256_encryptor.update(b'P' * 16) + aes256_encryptor.finalize()
    sm4_cipher = Cipher(algorithms.SM4(b"S" * 16), modes.ECB())
    sm4_encryptor = sm4_cipher.encryptor()
    sm4_ciphertext = sm4_encryptor.update(b'P' * 16) + sm4_encryptor.finalize()


# Targets ECCG-BLOCK-002 if the scanner records the attempted 160-bit AES key.
# PyCA rejects this constructor, so this is an invalid-usage snippet, not working AES.
def invalid_aes_key_size():
    invalid_key = b"K" * 20
    cipher = Cipher(algorithms.AES(invalid_key), modes.CBC(b"I" * 16))
    return cipher.encryptor()
