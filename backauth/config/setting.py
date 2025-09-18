import os

from jwt import jwk_from_pem, AbstractJWKBase
from pydantic_settings import BaseSettings, SettingsConfigDict
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


class TokenSettings(BaseSettings):
    private_key_path: str = ""
    public_key_path: str = ""
    algorithm: str = "RS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7

    @property
    def private_key(self)  -> AbstractJWKBase:
        if not os.path.exists(self.private_key_path):
            raise FileNotFoundError(f"Private key file not found: {self.private_key_path}")
        with open(self.private_key_path, "rb") as f:
            return  jwk_from_pem(f.read())

    @property
    def public_key(self) -> AbstractJWKBase:
        if not os.path.exists(self.public_key_path):
            raise FileNotFoundError(f"Private key file not found: {self.private_key_path}")
        with open(self.public_key_path, "rb") as f:
            return  jwk_from_pem(f.read())

class Config(BaseSettings):

    redirect_uri: str

    google: GoogleOAuth = GoogleOAuth()
    discord: DiscordOAuth = DiscordOAuth()
    github: GithubOAuth = GithubOAuth()

    token: TokenSettings = TokenSettings()
    redis: str = "redis://localhost:6379"
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



