from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, mldsa, padding, rsa

# ECCG-DG-001's rejection branch has no native PyCA example here: these public
# signature APIs implement agreed schemes. A weak curve belongs to ECCG-ECDLOG-001.


# Should not fire ECCG-DG-001 or ECCG-RSA-001: agreed signatures with 3072-bit RSA.
def rsa_signatures() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    message = b"example RSA signatures"
    pss_signature = private_key.sign(
        message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()
    )
    private_key.public_key().verify(
        pss_signature, message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()
    )
    pkcs1_signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    private_key.public_key().verify(pkcs1_signature, message, padding.PKCS1v15(), hashes.SHA256())


# Should not fire ECCG-DG-001; P-384 should fire the ECCG-ECDLOG-002 advisory.
def elliptic_curve_signatures() -> None:
    message = b"example elliptic curve signatures"
    ec_private_key = ec.generate_private_key(ec.SECP384R1())
    signature = ec_private_key.sign(message, ec.ECDSA(hashes.SHA384()))
    ec_private_key.public_key().verify(signature, message, ec.ECDSA(hashes.SHA384()))

    deterministic_signature = ec_private_key.sign(
        message, ec.ECDSA(hashes.SHA384(), deterministic_signing=True)
    )
    ec_private_key.public_key().verify(deterministic_signature, message, ec.ECDSA(hashes.SHA384()))

    ed25519_private_key = ed25519.Ed25519PrivateKey.generate()
    ed25519_signature = ed25519_private_key.sign(message)
    ed25519_private_key.public_key().verify(ed25519_signature, message)

    ed448_private_key = ed448.Ed448PrivateKey.generate()
    ed448_signature = ed448_private_key.sign(message)
    ed448_private_key.public_key().verify(ed448_signature, message)


# Should not fire ECCG-DG-001; the DSA domain may separately fire ECCG-FFDLOG-001.
def dsa_signature() -> None:
    private_key = dsa.generate_private_key(key_size=2048)
    message = b"example DSA signature"
    signature = private_key.sign(message, hashes.SHA256())
    private_key.public_key().verify(signature, message, hashes.SHA256())


# Should not fire ECCG-DG-001: ML-DSA is agreed. Requires PyCA 47+ and backend support.
def ml_dsa_signature() -> None:
    private_key = mldsa.MLDSA65PrivateKey.generate()
    message = b"example ML-DSA signature"
    signature = private_key.sign(message)
    private_key.public_key().verify(signature, message)
