from functools import lru_cache
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jose import jwk
from jose.backends.base import Key
from pydantic_settings import BaseSettings, SettingsConfigDict
from redis.asyncio import ConnectionPool


class OAuthBase(BaseSettings):
    client_id: str
    client_secret: str
    enabled: bool = False

    @property
    def id(self) -> str:
        if not self.client_id:
            raise RuntimeError(f"{self.__class__.__name__}: client_id is not set")
        return self.client_id

    @property
    def secret(self) -> str:
        if not self.client_secret:
            raise RuntimeError(f"{self.__class__.__name__}: client_secret is not set")
        return self.client_secret


class GithubOAuth(OAuthBase):
    client_id: str = ""
    client_secret: str = ""


class DiscordOAuth(OAuthBase):
    client_id: str = ""
    client_secret: str = ""


class GoogleOAuth(OAuthBase):
    client_id: str = ""
    client_secret: str = ""


SigningAlgorithm = Literal["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]


@lru_cache(maxsize=32)
def _load_key(path: str, algorithm: SigningAlgorithm, private: bool) -> Key:
    """Cache parsed keys per process; restart processes when rotating key files."""
    pem = Path(path).read_bytes()
    if private:
        key = serialization.load_pem_private_key(pem, password=None)
    else:
        key = serialization.load_pem_public_key(pem)
    if algorithm.startswith("ES"):
        curves = {"ES256": ec.SECP256R1, "ES384": ec.SECP384R1, "ES512": ec.SECP521R1}
        if not isinstance(
            key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)
        ) or not isinstance(key.curve, curves[algorithm]):
            raise ValueError(
                f"{algorithm} requires an ECC key on the corresponding curve"
            )
    elif not isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        raise ValueError(f"{algorithm} requires an RSA key")
    return jwk.construct(key, algorithm=algorithm)


class TokenSettings(BaseSettings):
    private_key_path: str = ""
    public_key_path: str = ""
    algorithm: SigningAlgorithm = "RS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7

    @property
    def private_key(self) -> Key:
        return _load_key(self.private_key_path, self.algorithm, private=True)

    @property
    def public_key(self) -> Key:
        return _load_key(self.public_key_path, self.algorithm, private=False)


class Config(BaseSettings):

    redirect_uri: str

    google: GoogleOAuth = GoogleOAuth()
    discord: DiscordOAuth = DiscordOAuth()
    github: GithubOAuth = GithubOAuth()

    token: TokenSettings = TokenSettings()
    redis_connection_pool: ConnectionPool
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
    )

    def __getitem__(self, key: str) -> OAuthBase:
        attr = getattr(self, key, None)
        if isinstance(attr, OAuthBase):
            return attr
        raise KeyError(f"Invalid or unsupported service name: {key}")
