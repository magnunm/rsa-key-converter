from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization

from .format import PrivateKeyFormat, PublicKeyFormat


class PEMPrivateKey(PrivateKeyFormat):
    @staticmethod
    def name() -> str:
        return "pem"

    @staticmethod
    def from_string(string_repr: str) -> RSAPrivateKey:
        try:
            key = serialization.load_pem_private_key(
                string_repr.encode("utf-8"), password=None
            )
        except Exception as e:
            raise ValueError(f"Could not parse key according to PEM format: {e}") from e
        if not isinstance(key, RSAPrivateKey):
            raise ValueError("Expected RSA key, instead got: ", type(key).__name__)
        return key

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


class PEMPublicKey(PublicKeyFormat):
    @staticmethod
    def name() -> str:
        return "pem"

    @staticmethod
    def from_string(string_repr: str) -> RSAPublicKey:
        try:
            key = serialization.load_pem_public_key(string_repr.encode("utf-8"))
        except Exception as e:
            raise ValueError(f"Could not parse key according to PEM format: {e}") from e
        if not isinstance(key, RSAPublicKey):
            raise ValueError(
                "Expected RSA public key, instead got: ", type(key).__name__
            )
        return key

    @staticmethod
    def to_string(key: RSAPublicKey) -> str:
        try:
            return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.PKCS1,
            ).decode()
        except Exception as e:
            raise ValueError(
                f"Could not serialize private key to PEM format: {e}"
            ) from e
