# RSA key converter

Command line tool to convert between PEM and JWK formats for RSA private and
public keys.

## Installation

Install using `poetry` by running:

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

## Examples

Convert a private key in PEM format to JWK format:

```
rsa-key-converter -i pem -o jwk '<prive key in pem format>'
```

Convert a public key in JWK format to PEM format:

```
rsa-key-converter -i jwk -o pem -m public '<public key in JWK format>'
```
