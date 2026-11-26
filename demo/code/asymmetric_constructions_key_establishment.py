from cryptography.hazmat.primitives.asymmetric import ec, mlkem, x25519, x448

# ECCG-KEE-001's rejection branch has no native example among these agreed APIs.
# PyCA 50 exposes ML-KEM-768/1024, not ML-KEM-512: ECCG-KEE-003 should not fire
# when the supported parameter sets are identified correctly.
# No public FrodoKEM API is available for an ECCG-KEE-004 example.


# Should fire ECCG-KEE-002 for authentication review; should not fire ECCG-KEE-001.
def classical_key_agreements() -> None:
    alice_ec_key = ec.generate_private_key(ec.SECP256R1())
    bob_ec_key = ec.generate_private_key(ec.SECP256R1())
    alice_ec_secret = alice_ec_key.exchange(ec.ECDH(), bob_ec_key.public_key())
    bob_ec_secret = bob_ec_key.exchange(ec.ECDH(), alice_ec_key.public_key())

    alice_x25519_key = x25519.X25519PrivateKey.generate()
    bob_x25519_key = x25519.X25519PrivateKey.generate()
    alice_x25519_secret = alice_x25519_key.exchange(bob_x25519_key.public_key())
    bob_x25519_secret = bob_x25519_key.exchange(alice_x25519_key.public_key())

    alice_x448_key = x448.X448PrivateKey.generate()
    bob_x448_key = x448.X448PrivateKey.generate()
    alice_x448_secret = alice_x448_key.exchange(bob_x448_key.public_key())
    bob_x448_secret = bob_x448_key.exchange(alice_x448_key.public_key())


# Should fire ECCG-KEE-002; known ML-KEM-768/1024 sets should not fire ECCG-KEE-003.
def ml_kem_encapsulation() -> None:
    recipient_768_key = mlkem.MLKEM768PrivateKey.generate()
    shared_secret_768, ciphertext_768 = recipient_768_key.public_key().encapsulate()
    recovered_secret = recipient_768_key.decapsulate(ciphertext_768)

    recipient_1024_key = mlkem.MLKEM1024PrivateKey.generate()
    shared_secret_1024, ciphertext_1024 = recipient_1024_key.public_key().encapsulate()
    recovered_secret = recipient_1024_key.decapsulate(ciphertext_1024)
