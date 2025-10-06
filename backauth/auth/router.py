from typing import Annotated, Type, Any
from fastapi import APIRouter, Depends, Form
from fastapi.security import OAuth2PasswordRequestForm

from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Request
from fastapi.responses import RedirectResponse

from backauth.auth.model.token import TokenOrm
from backauth.auth.schemas import Token
from backauth.config.setting import Config, OAuthBase
from backauth.user.model import UserOrm
from backauth.user.schema import UserLoginSchema
from backauth.user.service import UserService


def oauth_router(
    get_session: Any,
    token_model: Type[TokenOrm],
    user_model: Type[UserOrm],
    configuration: Config,
):
    router = APIRouter(prefix="/oauth", tags=["oauth"])

    def create_user_service_dep(
        session: AsyncSession = Depends(get_session),
    ) -> UserService:
        return UserService(session, user_model, token_model, configuration)

    service_user = Annotated[UserService, Depends(create_user_service_dep)]

    @router.get("/code")
    async def redirect_code(
        code: str, state: str, service: service_user
    ) -> RedirectResponse:
        front, res = await service.create_user_from_oauth(code, state)
        response = RedirectResponse(
            url=front
            + "#access_token="
            + res.access_token
            + "&refresh_token="
            + res.refresh_token
            + "&token_type=bearer",
            status_code=302,
        )
        return response

    for field, value in configuration.__dict__.items():
        if isinstance(value, OAuthBase) and value.enabled:

            @router.get(f"/{field}", response_model=str)
            async def login(
                service: service_user, request: Request, redirect_url: str
            ) -> str:
                endpoint_name = request.url.path.split("/")[-1]
                return service.get_auth_url(endpoint_name, redirect_url)

    return router


def login_router(
    get_session: Any,
    token_model: Type[TokenOrm],
    user_model: Type[UserOrm],
    configuration: Config,
):

    router = APIRouter(prefix="/auth", tags=["auth"])

    def create_user_service_dep(
        session: AsyncSession = Depends(get_session),
    ) -> UserService:
        return UserService(session, user_model, token_model, configuration)

    service_user = Annotated[UserService, Depends(create_user_service_dep)]

    @router.post("/login")
    async def login(
        service: service_user,
        form_data: OAuth2PasswordRequestForm = Depends(),
    ) -> Token:
        data = UserLoginSchema(email=form_data.username, password=form_data.password)
        return await service.login(data)

    @router.post("/token")
    async def login_for_access_token(
        service: service_user, refresh_token: str = Form(...)
    ) -> Token:
        return await service.get_token_by_refresh(refresh_token)

    return router
