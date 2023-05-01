"""Convert between RSA private and public key formats.

Shorthand names for RSA numbers:
n = The public modulus
e = The public exponent
p = One of the primes composing n
q = The other of the primes composing n
d = The private exponent

"""
from argparse import ArgumentParser

from .formats import PrivateKeyFormat, PublicKeyFormat, JWKPrivateKey, PEMPrivateKey


PRIVATE_KEY_FORMATS: list[type[PrivateKeyFormat]] = [JWKPrivateKey, PEMPrivateKey]
PUBLIC_KEY_FORMATS: list[type[PublicKeyFormat]] = []


def main():
    private_key_formats = {f.name(): f for f in PRIVATE_KEY_FORMATS}
    public_key_formats = {f.name(): f for f in PUBLIC_KEY_FORMATS}

    arg_parser = ArgumentParser(
        description=(
            "Convert between RSA key formats. "
            f"Supported private key formats: {' '.join(private_key_formats.keys())}. "
            f"Supported public key formats: {' '.join(public_key_formats.keys())}."
        )
    )
    arg_parser.add_argument(
        "input",
        help="Key in input format that will be converted to output format",
    )
    arg_parser.add_argument(
        "-m",
        "--mode",
        help="Mode: Convert `private` or `public` keys, default: `private`.",
        default="private",
    )
    arg_parser.add_argument(
        "-i",
        "--input_format",
        help="Key format for the input.",
    )
    arg_parser.add_argument(
        "-o",
        "--output_format",
        help="Key format for the output.",
    )

    args = arg_parser.parse_args()

    if args.mode not in ("public", "private"):
        print("Unsupported mode:", args.mode)
        return

    formats = private_key_formats if args.mode == "private" else public_key_formats

    if args.input_format not in formats.keys():
        print("Unsupported input format for mode", args.mode, ":", args.input_format)
        return
    input_format = formats[args.input_format]

    if args.output_format not in formats.keys():
        print("Unsupported output format for mode", args.mode, ":", args.input_format)
        return
    output_format = formats[args.output_format]

    input_key = args.input

    try:
        key = input_format.from_string(input_key)
        print(output_format.to_string(key))
    except ValueError as e:
        print(str(e))
        return
