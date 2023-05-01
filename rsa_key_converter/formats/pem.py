from .format import PrivateKeyFormat

from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
)
from cryptography.hazmat.primitives import serialization


class PEMPrivateKey(PrivateKeyFormat):
    @staticmethod
    def name() -> str:
        return "pem"

    @staticmethod
    def from_string(string_repr: str) -> RSAPrivateKey:
        ...

    @staticmethod
    def to_string(key: RSAPrivateKey) -> str:
        try:
            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode()
        except Exception as e:
            raise ValueError(
                f"Could not serialize private key to PEM format: {e}"
            ) from e
