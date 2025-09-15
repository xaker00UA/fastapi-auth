from typing import Annotated, Type
from fastapi import APIRouter, Depends, Body

from sqlalchemy.ext.asyncio import AsyncSession

from backauth.auth.model.token import TokenOrm
from backauth.auth.schemas import Token
from backauth.config.setting import Config, OAuthBase, config
from backauth.user.model import UserOrm
from backauth.user.schema import UserLoginSchema
from backauth.user.service import UserService


def oauth_router(
    session: AsyncSession,
    token_model: Type[TokenOrm],
    user_model: Type[UserOrm],
    configuration: Config | None = None,
):
    if configuration is None:
        configuration = config
    oauth_router = APIRouter(prefix="/oauth", tags=["oauth"])

    def create_user_service_dep() -> UserService:
        return UserService(session, user_model, token_model, configuration)

    service_user = Annotated[UserService, Depends(create_user_service_dep)]

    @oauth_router.get("/code")
    async def redirect_code(code: str, state: str, service: service_user) -> Token:
        return await service.create_user_from_oauth(code, state)

    for cfg in configuration:
        if isinstance(cfg, OAuthBase) and cfg.enabled:

            @oauth_router.get(f"/{cfg.name}", response_model=str)
            async def login(service: service_user) -> str:
                return service.get_auth_url(cfg.name)

    return oauth_router


def login_router(
    session: AsyncSession,
    token_model: Type[TokenOrm],
    user_model: Type[UserOrm],
    configuration: Config | None = None,
):
    if configuration is None:
        configuration = config

    login_router = APIRouter(prefix="/auth", tags=["auth"])

    def create_user_service_dep() -> UserService:
        return UserService(session, user_model, token_model, configuration)

    service_user = Annotated[UserService, Depends(create_user_service_dep)]

    @login_router.post("/login")
    async def login(form_data: UserLoginSchema, service: service_user) -> Token:
        return await service.login(form_data)

    @login_router.post("/token")
    async def login_for_access_token(
        service: service_user, refresh_token: str = Body(...)
    ) -> Token:
        return await service.get_token_by_refresh(refresh_token)

    return login_router
