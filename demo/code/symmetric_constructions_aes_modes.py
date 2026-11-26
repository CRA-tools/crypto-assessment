from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers import modes as legacy_modes


# Should fire ECCG-SYM-ENC-001: ECB is not an agreed encryption mode.
def aes_ecb_encryption():
    key = b"K" * 16  # AES-128 key

    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
    )

    encryptor = cipher.encryptor()

    # ECB requires input length to be a multiple of AES block size: 16 bytes.
    plaintext = b"A" * 16

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return ciphertext


# Should fire ECCG-SYM-ENC-002/003 advisories; these modes should not fire ECCG-SYM-ENC-001.
def agreed_mode_examples() -> None:
    import os

    key = os.urandom(32)
    plaintext = b"A" * 32
    ciphers = [
        Cipher(algorithms.AES(key), modes.CTR(os.urandom(16))),
        Cipher(algorithms.AES(key), modes.CBC(os.urandom(16))),
        Cipher(algorithms.AES(key), legacy_modes.CFB(os.urandom(16))),
        Cipher(algorithms.AES(key), legacy_modes.OFB(os.urandom(16))),
    ]
    for cipher in ciphers:
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        decryptor = cipher.decryptor()
        recovered_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
