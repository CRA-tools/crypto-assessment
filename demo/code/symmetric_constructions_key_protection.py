import os

from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESSIV


# KW/KWP/SIV should not fire ECCG-KP-001 when correctly classified; GCM should fire it.
def key_protection_examples() -> None:
    wrapping_key = os.urandom(32)
    content_key = os.urandom(32)
    wrapped_key = keywrap.aes_key_wrap(wrapping_key, content_key)
    unwrapped_key = keywrap.aes_key_unwrap(wrapping_key, wrapped_key)

    short_key_material = os.urandom(21)
    padded_wrapped_key = keywrap.aes_key_wrap_with_padding(wrapping_key, short_key_material)
    unwrapped_short_key = keywrap.aes_key_unwrap_with_padding(wrapping_key, padded_wrapped_key)

    siv_key = AESSIV.generate_key(bit_length=512)
    siv = AESSIV(siv_key)
    wrapped_with_siv = siv.encrypt(content_key, [b"example key identifier"])
    unwrapped_siv_key = siv.decrypt(wrapped_with_siv, [b"example key identifier"])

    gcm_wrapping_key = AESGCM.generate_key(bit_length=256)
    gcm = AESGCM(gcm_wrapping_key)
    nonce = os.urandom(12)
    wrapped_with_gcm = gcm.encrypt(nonce, content_key, b"example key identifier")
    unwrapped_gcm_key = gcm.decrypt(nonce, wrapped_with_gcm, b"example key identifier")
