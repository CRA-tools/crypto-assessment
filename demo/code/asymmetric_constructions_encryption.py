from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ECCG-AS-ENC-001 rejects other schemes or insufficient scheme evidence.
# PyCA's native RSA encryption requires OAEP or PKCS1v15, both agreed schemes.


# OAEP should fire ECCG-AS-ENC-002/004/005; PKCS1v15 should fire ECCG-AS-ENC-002/003/005.
def rsa_encryption_examples() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()
    plaintext = b"example asymmetric encryption"

    oaep_ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    oaep_plaintext = private_key.decrypt(
        oaep_ciphertext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    pkcs1_ciphertext = public_key.encrypt(plaintext, padding.PKCS1v15())
    pkcs1_plaintext = private_key.decrypt(pkcs1_ciphertext, padding.PKCS1v15())
