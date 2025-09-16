from typing import Annotated, Type, AsyncGenerator, Any
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backauth.auth.model.token import TokenOrm
from backauth.auth.service.token_service import TokenService
from backauth.config.setting import Config
from backauth.user.model import UserOrm
from backauth.user.schema import (
    UserRegisterSchema,
    UserResponseSchema,
    UserUpdateSchema,
)
from backauth.user.service import UserService
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    HTTPBearer,
    HTTPAuthorizationCredentials,
)


def users_router(
    get_session: Any,
    token_model: Type[TokenOrm],
    user_model: Type[UserOrm],
    configuration: Config,
):
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", refreshUrl="auth/token")

    def create_user_service_dep(
        session: AsyncSession = Depends(get_session),
    ) -> UserService:
        return UserService(session, user_model, token_model, configuration)

    def create_token_service(
        session: AsyncSession = Depends(get_session),
    ) -> TokenService:
        return TokenService(session, token_model, configuration)

    async def is_authenticated(token: str = Depends(oauth2_scheme)) -> bool:
        service_token = create_token_service()
        return await service_token.validate_token(token)

    router = APIRouter(
        prefix="", tags=["users"], dependencies=[Depends(is_authenticated)]
    )
    public_router = APIRouter(prefix="/users", tags=["users"])
    service_user = Annotated[UserService, Depends(create_user_service_dep)]
    service_token_depends = Annotated[TokenService, Depends(create_token_service)]

    @router.get("/me", response_model=UserResponseSchema)
    async def read_users_me(
        service: service_token_depends, token: HTTPAuthorizationCredentials
    ):
        return service.get_token_info(token.credentials)

    @public_router.post("/", response_model=UserResponseSchema)
    async def create_user(user: UserRegisterSchema, service: service_user):
        return await service.register(user)

    @router.put("/{_id}", status_code=204)
    async def update_user(
        _id: UUID, form_data: UserUpdateSchema, service: service_user
    ):
        return service.update_user(_id, form_data)

    @router.delete("/{_id}", status_code=204)
    async def delete_user(_id: UUID, service: service_user):
        return service.delete_user(_id)

    @router.get("/{_id}", response_model=UserResponseSchema)
    async def get_user(_id: UUID, service: service_user):
        return service.get_user(_id)

    public_router.include_router(router)
    return public_router
