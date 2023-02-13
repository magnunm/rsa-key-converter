"""Convert between RSA private and public key formats.

Shorthand names for RSA numbers:
n = The public modulus
e = The public exponent
p = One of the primes composing n
q = The other of the primes composing n
d = The private exponent

"""
from argparse import ArgumentParser
import json
import base64

from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicNumbers,
    RSAPrivateNumbers,
    RSAPrivateKey,
    rsa_crt_iqmp,
    rsa_crt_dmp1,
    rsa_crt_dmq1,
)
from cryptography.hazmat.primitives import serialization


def main():
    arg_parser = ArgumentParser(description="Convert between RSA key formats")
    arg_parser.add_argument(
        "-jwk",
        "--private_key_jwk_format",
        help="RSA key in JWK format, as defined in RFC 7518 section 6.3.",
    )

    args = arg_parser.parse_args()

    if args.private_key_jwk_format:
        private_key = private_key_from_jwk_format(args.private_key_jwk_format)
        if private_key:
            print("PRIVATE KEY IN PEM FORMAT:\n")
            print(private_key_to_PEM_format(private_key))
        return

    print("No private key provided for conversion")


def private_key_from_jwk_format(jwk: str) -> RSAPrivateKey:
    try:
        jwk = json.loads(jwk)
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

    return private_key_from_numbers(n, e, p, q, d)


def private_key_from_numbers(n: int, e: int, p: int, q: int, d: int) -> RSAPrivateKey:
    rsa_public_key_numbers = RSAPublicNumbers(e, n)

    dmp1 = rsa_crt_dmp1(d, p)
    dmq1 = rsa_crt_dmq1(d, q)
    iqmp = rsa_crt_iqmp(p, q)

    return RSAPrivateNumbers(
        p, q, d, dmp1, dmq1, iqmp, rsa_public_key_numbers
    ).private_key()


def private_key_to_PEM_format(private_key: RSAPrivateKey) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


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
    number_as_bytes = base64.urlsafe_b64decode(number_as_base64_urlsafe + "==")
    return int.from_bytes(number_as_bytes, byteorder="big", signed=False)


if __name__ == "__main__":
    main()
