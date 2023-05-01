import json
import base64

from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPrivateNumbers,
    rsa_crt_iqmp,
    rsa_crt_dmp1,
    rsa_crt_dmq1,
    RSAPublicNumbers,
)

from .format import PrivateKeyFormat


class JWKPrivateKey(PrivateKeyFormat):
    @staticmethod
    def name() -> str:
        return "jwk"

    @staticmethod
    def from_string(string_repr: str) -> RSAPrivateKey:
        try:
            jwk = json.loads(string_repr)
        except json.JSONDecodeError as e:
            raise ValueError("Invalid JWK format: Not valid JSON") from e

        try:
            n = number_from_base64_urlssafe_uint(jwk["n"])
            e = number_from_base64_urlssafe_uint(jwk["e"])
            p = number_from_base64_urlssafe_uint(jwk["p"])
            q = number_from_base64_urlssafe_uint(jwk["q"])
            d = number_from_base64_urlssafe_uint(jwk["d"])
        except KeyError as e:
            raise ValueError(
                "Invalid JWK format for RSA private key. Numbers n, e, p, q and d are required."
            ) from e
        except ValueError as e:
            raise ValueError(f"Invalid JWK format for RSA private key: {e}") from e

        return private_key_from_numbers(n, e, p, q, d)

    @staticmethod
    def to_string(key: RSAPrivateKey) -> str:
        ...


def private_key_from_numbers(n: int, e: int, p: int, q: int, d: int) -> RSAPrivateKey:
    try:
        rsa_public_key_numbers = RSAPublicNumbers(e, n)

        dmp1 = rsa_crt_dmp1(d, p)
        dmq1 = rsa_crt_dmq1(d, q)
        iqmp = rsa_crt_iqmp(p, q)

        return RSAPrivateNumbers(
            p, q, d, dmp1, dmq1, iqmp, rsa_public_key_numbers
        ).private_key()
    except Exception as exc:
        raise ValueError(f"Invalid RSA private key numbers: {exc}")


def number_from_base64_urlssafe_uint(number_as_base64_urlsafe: str) -> int:
    """Decode a Base64urlUInt encoded integer.

    As per RFC 7518 section 6.3 (https://www.rfc-editor.org/rfc/rfc7518#section-6.3) the
    parameters for RSA keys in JWKs are "Base64urlUInt-encoded". This encoding is in turn
    defined as:

    > The representation of a positive or zero integer value as the
    > base64url encoding of the value's unsigned big-endian
    > representation as an octet sequence.

    """
    # Add `==` to work around missing padding in the Base64 number. Extra padding will be
    # truncated by `base64` and therefore we can add the maximum amount of padding (two `=`)
    # to always have sufficient padding.
    try:
        number_as_bytes = base64.urlsafe_b64decode(number_as_base64_urlsafe + "==")
        return int.from_bytes(number_as_bytes, byteorder="big", signed=False)
    except Exception as e:
        raise ValueError(
            f"Expected Base64urlUInt encoded integer, got error: {e}"
        ) from e