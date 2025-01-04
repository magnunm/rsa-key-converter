# RSA key converter

Convert between RSA private and public keys in PEM and JWK formats.

## Installation

In the root of this repository:

```sh
poetry install
poetry build
pip install .
```

Replace the last step with `pipx install .` for an isolated install with
[pipx](https://github.com/pypa/pipx).

## Usage

```sh
rsa-key-converter --help
```

## Example

Convert a private key in PEM format to JWK format:

```
rsa-key-converter -i pem -o jwk '<key in pem format>'
```
