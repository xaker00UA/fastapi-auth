from typing import Annotated, Type, AsyncGenerator, Any
from uuid import UUID
from fastapi.exceptions import HTTPException
from fastapi import status
from fastapi import APIRouter, Depends, Body
from sqlalchemy.ext.asyncio import AsyncSession

from backauth.auth.model.token import TokenOrm
from backauth.auth.service.token_service import TokenService
from backauth.config.setting import Config
from backauth.user.model import UserOrm
from backauth.user.schema import (
    UserRegisterSchema,
    UserResponseSchema,
    UserUpdateSchema,
    UserPayloadSchema,
)
from backauth.user.service import UserService
from fastapi.security import (
    OAuth2PasswordBearer,
)
from fastapi import Path


def users_router(
    get_session: Any,
    token_model: Type[TokenOrm],
    user_model: Type[UserOrm],
    user_read_schema: type[UserResponseSchema],
    user_update_schema: type[UserUpdateSchema],
    user_register_schema: type[UserRegisterSchema],
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

    async def is_authenticated(
        token: str = Depends(oauth2_scheme),
    ):
        service_token = create_token_service()

        if not await service_token.validate_token(token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            )

    async def is_owner(
        _id: UUID = Path(),
        token: str = Depends(oauth2_scheme),
    ):
        service_token = create_token_service()
        user = service_token.get_token_info(token)
        if user.get("user_id") != str(_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access forbidden: You don't have permission to access this user's data",
            )

    router = APIRouter(
        prefix="", tags=["users"], dependencies=[Depends(is_authenticated)]
    )
    public_router = APIRouter(prefix="/users", tags=["users"])
    service_user = Annotated[UserService, Depends(create_user_service_dep)]
    service_token_depends = Annotated[TokenService, Depends(create_token_service)]

    @router.get("/me", response_model=UserPayloadSchema)
    async def read_users_me(
        service: service_token_depends, token: str = Depends(oauth2_scheme)
    ):
        return service.get_token_info(token)

    @public_router.post("/", response_model=user_read_schema)
    async def create_user(user: user_register_schema, service: service_user):  # type: ignore
        return await service.register(user)

    @router.put("/{_id}", status_code=204, dependencies=[Depends(is_owner)])
    async def update_user(
        _id: UUID,
        service: service_user,
        form_data: user_update_schema,  # type: ignore
    ):
        return await service.update_user(_id, form_data)

    @router.delete("/{_id}", status_code=204, dependencies=[Depends(is_owner)])
    async def delete_user(_id: UUID, service: service_user):
        return await service.delete_user(_id)

    @router.get(
        "/{_id}", response_model=user_read_schema, dependencies=[Depends(is_owner)]
    )
    async def get_user(_id: UUID, service: service_user):
        return await service.get_user(_id)

    public_router.include_router(router)
    return public_router
