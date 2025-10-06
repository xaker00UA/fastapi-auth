from typing import Any, TypeVar, Generic, Type

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from backauth.auth.service import *  # type: ignore
from backauth.auth.model.token import TokenOrm
from backauth.auth.schemas import UserType, TokenType
from backauth.auth.service.token_service import TokenService
from backauth.config.setting import Config

V = TypeVar("V", bound=TokenType)


class AuthService(Generic[V]):
    service_name: str = NotImplementedError  # type: ignore
    model: Type[V] = NotImplementedError  # type: ignore

    _service_urls = {
        "google": "https://accounts.google.com/o/oauth2/v2/auth",
        "github": "https://github.com/login/oauth/authorize",
        "discord": "https://discord.com/oauth2/authorize",
    }
    _token_urls = {
        "google": "https://oauth2.googleapis.com/token",
        "github": "https://github.com/login/oauth/access_token",
        "discord": "https://discord.com/api/oauth2/token",
    }
    _scope = {
        "google": "https://www.googleapis.com/auth/userinfo.email "
        + "https://www.googleapis.com/auth/userinfo.profile openid",
        "github": "read:user user:email user:follow",
        "discord": "identify email",
    }

    def __init__(
        self,
        db: AsyncSession,
        token_model: Type[TokenOrm],
        configuration: Config,
    ) -> None:
        self.conf = configuration
        self.token_service = TokenService(db, token_model, configuration)
        self.db = db
        self.token_model = token_model

    async def get_user(self, token) -> UserType:
        raise NotImplementedError

    def build_params_auth(self, service: str) -> dict[str, str]:
        data: dict[str, dict[str, Any]] = {
            "google": {
                "prompt": "consent",
                "access_type": "offline",
                "response_type": "code",
                "scope": self._scope[service],
            },
            "github": {"scope": self._scope[service]},
            "discord": {
                "response_type": "code",
                "scope": self._scope[service],
            },
        }
        return data[service]

    def build_params_token(self, service: str) -> dict[str, str]:
        data: dict[str, dict[str, str]] = {
            "google": {
                "grant_type": "authorization_code",
                "granted_scopes": self._scope[service],
            },
            "github": {},
            "discord": {
                "grant_type": "authorization_code",
            },
        }
        return data[service]

    async def get_token(self, code: str, state: str) -> V:
        service = await self.valid_state(state)
        query_params = {
            "code": code,
            "client_id": self.conf[service].id,
            "client_secret": self.conf[service].secret,
            "redirect_uri": self.conf.redirect_uri,
            **self.build_params_token(service),
        }
        async with AsyncClient() as client:
            response = await client.post(
                self._token_urls[self.service_name],
                params=query_params,
                headers={"Accept": "application/json"},
            )
            if response.status_code == 200:
                data = response.json()
                token = self.model.model_validate(data)
                return token
            raise Exception("Invalid code")

    def get_auth_url(self, service: str, redirect_url: str) -> str:
        query_params = {
            "client_id": self.conf[service].id,
            "redirect_uri": self.conf.redirect_uri,
            "state": self.generate_state(service, redirect_url),
            **self.build_params_auth(service),
        }
        return (
            self._service_urls[service]
            + "?"
            + "&".join([f"{key}={value}" for key, value in query_params.items()])
        )

    def generate_state(self, service: str, redirect_uri: str):
        return self.token_service.create_access_token(
            {
                "service": service,
                "redirect_url": redirect_uri,
            }
        )

    async def valid_state(self, state: str) -> str:
        await self.token_service.validate_token(state)
        return self.token_service.get_token_info(state).get("service", "")

    def get_service(self, service: str):
        for subclass in AuthService.__subclasses__():
            if getattr(subclass, "service_name", None) == service:
                return subclass(self.db, self.token_model, self.conf)
        raise Exception("Invalid service")

    async def get_service_by_state(self, state: str):
        return self.get_service(await self.valid_state(state))
