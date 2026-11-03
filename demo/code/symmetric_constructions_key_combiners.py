import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Should fire ECCG-KC-001 when ECDH, X25519 and HKDF have occurrences in this file.
def classical_secret_combination() -> None:
    alice_ec_key = ec.generate_private_key(ec.SECP256R1())
    bob_ec_key = ec.generate_private_key(ec.SECP256R1())
    alice_ec_secret = alice_ec_key.exchange(ec.ECDH(), bob_ec_key.public_key())
    bob_ec_secret = bob_ec_key.exchange(ec.ECDH(), alice_ec_key.public_key())

    alice_x25519_key = x25519.X25519PrivateKey.generate()
    bob_x25519_key = x25519.X25519PrivateKey.generate()
    alice_x25519_secret = alice_x25519_key.exchange(bob_x25519_key.public_key())
    bob_x25519_secret = bob_x25519_key.exchange(alice_x25519_key.public_key())

    salt = os.urandom(32)
    alice_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"demo ECDH X25519 combination"
    ).derive(alice_ec_secret + alice_x25519_secret)
    bob_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"demo ECDH X25519 combination"
    ).derive(bob_ec_secret + bob_x25519_secret)


# Should fire ECCG-KC-001 when X25519, ML-KEM and HKDF are detected together.
def classical_and_pq_secret_combination() -> None:
    alice_key = x25519.X25519PrivateKey.generate()
    bob_key = x25519.X25519PrivateKey.generate()
    alice_classical_secret = alice_key.exchange(bob_key.public_key())
    bob_classical_secret = bob_key.exchange(alice_key.public_key())

    recipient_kem_key = mlkem.MLKEM768PrivateKey.generate()
    alice_kem_secret, ciphertext = recipient_kem_key.public_key().encapsulate()
    bob_kem_secret = recipient_kem_key.decapsulate(ciphertext)

    salt = os.urandom(32)
    alice_combined_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"demo X25519 ML-KEM combination"
    ).derive(alice_classical_secret + alice_kem_secret)
    bob_combined_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"demo X25519 ML-KEM combination"
    ).derive(bob_classical_secret + bob_kem_secret)
