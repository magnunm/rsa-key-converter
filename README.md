# RSA key converter

Convert between different RSA private and public key formats.
Currently supports PEM and JWK formats.

## Installation

In the root of this repository:

```sh
poetry install
poetry build
pip install .
```

## Usage

```sh
rsa-key-converter --help
```

## Example

Convert a private key in PEM format to JWK format:

```
rsa-key-converter -i pem -o jwk '<key in pem format>'
```
