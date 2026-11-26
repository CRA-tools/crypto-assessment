from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# Targets ECCG-RSA-KEY-001/002 when material is detected; this section is disabled in main.
def key_serialization_examples() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    password = b"demo key serialization password"
    encrypted_private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )
    loaded_private_key = serialization.load_pem_private_key(encrypted_private_pem, password)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    loaded_public_key = serialization.load_pem_public_key(public_pem)
