from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


# P-256 should fire ECCG-ECDLOG-002; secp256k1 should fire ECCG-ECDLOG-001 if preserved.
def ecdsa_curve_examples() -> None:
    message = b"example curve assessment"
    p256_private_key = ec.generate_private_key(ec.SECP256R1())
    p256_signature = p256_private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    p256_private_key.public_key().verify(p256_signature, message, ec.ECDSA(hashes.SHA256()))

    secp256k1_private_key = ec.generate_private_key(ec.SECP256K1())
    # A different digest keeps this distinct from the P-256 signature when the
    # analyzer deduplicates signatures by algorithm name.
    secp256k1_signature = secp256k1_private_key.sign(message, ec.ECDSA(hashes.SHA512()))
    secp256k1_private_key.public_key().verify(secp256k1_signature, message, ec.ECDSA(hashes.SHA512()))
