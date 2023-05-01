from __future__ import annotations
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)


class PrivateKeyFormat(ABC):
    @staticmethod
    @abstractmethod
    def name() -> str:
        ...

    @staticmethod
    @abstractmethod
    def from_string(string_repr: str) -> RSAPrivateKey:
        ...

    @staticmethod
    @abstractmethod
    def to_string(key: RSAPrivateKey) -> str:
        ...


class PublicKeyFormat(ABC):
    @staticmethod
    @abstractmethod
    def name() -> str:
        ...

    @staticmethod
    @abstractmethod
    def from_string(string_repr: str) -> RSAPublicKey:
        ...

    @staticmethod
    @abstractmethod
    def to_string(key: RSAPublicKey) -> str:
        ...
