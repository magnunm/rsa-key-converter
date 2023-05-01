"""Convert between RSA private and public key formats."""
from __future__ import annotations
from typing import Union, Optional
from argparse import ArgumentParser
from dataclasses import dataclass

from .formats import (
    PrivateKeyFormat,
    PublicKeyFormat,
    JWKPrivateKey,
    JWKPublicKey,
    PEMPrivateKey,
    PEMPublicKey,
)


PRIVATE_KEY_FORMATS: dict[str, type[PrivateKeyFormat]] = {
    f.name(): f for f in [JWKPrivateKey, PEMPrivateKey]
}
PUBLIC_KEY_FORMATS: dict[str, type[PublicKeyFormat]] = {
    f.name(): f for f in [JWKPublicKey, PEMPublicKey]
}


def main():
    args = parse_args()
    if not args:
        return

    try:
        print(args.input_output_formats.convert_key(args.input))
    except ValueError as e:
        print(str(e))


@dataclass
class Args:
    input: str
    input_output_formats: Union[InputOutputFormatsPrivate, InputOutputFormatsPublic]


@dataclass
class InputOutputFormatsPublic:
    input_format: type[PublicKeyFormat]
    output_format: type[PublicKeyFormat]

    def convert_key(self, input_key: str) -> str:
        return self.output_format.to_string(self.input_format.from_string(input_key))


@dataclass
class InputOutputFormatsPrivate:
    input_format: type[PrivateKeyFormat]
    output_format: type[PrivateKeyFormat]

    def convert_key(self, input_key: str) -> str:
        return self.output_format.to_string(self.input_format.from_string(input_key))


def parse_args() -> Optional[Args]:
    arg_parser = ArgumentParser(
        description=(
            "Convert between RSA key formats. "
            f"Supported private key formats: {' '.join(PRIVATE_KEY_FORMATS.keys())}. "
            f"Supported public key formats: {' '.join(PUBLIC_KEY_FORMATS.keys())}."
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
        required=True,
    )
    arg_parser.add_argument(
        "-o",
        "--output_format",
        help="Key format for the output.",
        required=True,
    )

    args = arg_parser.parse_args()

    if args.mode not in ("public", "private"):
        print("Unsupported mode:", args.mode)
        return

    formats = PRIVATE_KEY_FORMATS if args.mode == "private" else PUBLIC_KEY_FORMATS

    if args.input_format not in formats.keys():
        print("Unsupported input format for mode", args.mode, ":", args.input_format)
        return
    input_format = formats[args.input_format]

    if args.output_format not in formats.keys():
        print("Unsupported output format for mode", args.mode, ":", args.input_format)
        return
    output_format = formats[args.output_format]

    return Args(
        input=args.input,
        input_output_formats=(
            InputOutputFormatsPrivate(input_format, output_format)  # type: ignore
            if args.mode == "private"
            else InputOutputFormatsPublic(input_format, output_format)  # type: ignore
        ),
    )
