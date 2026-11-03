from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# Should fire ECCG-RSA-001: 1024 bits is below the 3000-bit minimum.
def rsa_1024_example() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    message = b"undersized RSA example"
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    private_key.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())


# Should fire ECCG-RSA-001: 2048 bits is below the 3000-bit minimum.
def rsa_2048_example() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    message = b"undersized RSA example"
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA384())
    private_key.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA384())


# Should not fire ECCG-RSA-001: 3072 bits meets the modulus minimum.
def rsa_3072_example() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    message = b"RSA example meeting the modulus minimum"
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA512())
    private_key.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA512())
