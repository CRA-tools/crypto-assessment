from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh


# RFC 7919 public group parameters, not private key material.
FFDHE2048_PARAMETERS_PEM = b"""-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
"""


FFDHE3072_PARAMETERS_PEM = b"""-----BEGIN DH PARAMETERS-----
MIIBiAKCAYEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEfz9zeNVs7ZRkDW7w09N75nAI4YbRvydbmyQd62R0mkff3
7lmMsPrBhtkcrv4TCYUTknC0EwyTvEN5RPT9RFLi103TZPLiHnH1S/9croKrnJ32
nuhtK8UiNjoNq8Uhl5sN6todv5pC1cRITgq80Gv6U93vPBsg7j/VnXwl5B0rZsYu
N///////////AgEC
-----END DH PARAMETERS-----
"""


# Should fire ECCG-FFDLOG-001: this generated DH domain is not an identified agreed group.
def unagreed_dh_domain() -> None:
    parameters = dh.generate_parameters(generator=2, key_size=1024)
    alice_private_key = parameters.generate_private_key()
    bob_private_key = parameters.generate_private_key()
    alice_secret = alice_private_key.exchange(bob_private_key.public_key())
    bob_secret = bob_private_key.exchange(alice_private_key.public_key())


# Should not fire ECCG-FFDLOG-001/002 when the named ffdhe3072 group is recorded.
def named_ffdhe3072_domain() -> None:
    parameters = serialization.load_pem_parameters(FFDHE3072_PARAMETERS_PEM)
    alice_private_key = parameters.generate_private_key()
    bob_private_key = parameters.generate_private_key()
    alice_secret = alice_private_key.exchange(bob_private_key.public_key())
    bob_secret = bob_private_key.exchange(alice_private_key.public_key())


# Should fire ECCG-FFDLOG-002 if ffdhe2048 is recorded: 2048 bits is below 3072.
def named_ffdhe2048_domain() -> None:
    parameters = serialization.load_pem_parameters(FFDHE2048_PARAMETERS_PEM)
    alice_private_key = parameters.generate_private_key()
    bob_private_key = parameters.generate_private_key()
    alice_secret = alice_private_key.exchange(bob_private_key.public_key())
    bob_secret = bob_private_key.exchange(alice_private_key.public_key())
