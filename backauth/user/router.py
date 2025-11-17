from typing import Annotated, Type, AsyncGenerator, Any, Awaitable, Callable
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


def users_router(
    get_session: Any,
    token_model: Type[TokenOrm],
    user_model: Type[UserOrm],
    user_read_schema: type[UserResponseSchema],
    user_update_schema: type[UserUpdateSchema],
    user_register_schema: type[UserRegisterSchema],
    dependency_overrides: dict[str, Callable],
    configuration: Config,
) -> APIRouter:
    """
    Creates and configures the users router with authentication and CRUD operations.

    Args:
        get_session: Session factory function for database access.
        token_model: Token ORM model class.
        user_model: User ORM model class.
        user_read_schema: Schema for user response data.
        user_update_schema: Schema for user update data.
        user_register_schema: Schema for user registration data.
        dependency_overrides: Dictionary of dependency overrides. Should contain:
            - is_authenticated: Dependency function for authentication path /@me.
            - update_delete_get: Dependency function for CRUD operations.
        configuration: Application configuration.

    Returns:
        Configured FastAPI router for user endpoints.
    """

    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", refreshUrl="auth/token")

    def create_user_service_dep(
        session: AsyncSession = Depends(get_session),
    ) -> UserService:
        """Creates UserService dependency instance.

        Args:
            session: Database session

        Returns:
            Configured UserService instance
        """
        return UserService(session, user_model, token_model, configuration)

    def create_token_service(
        session: AsyncSession = Depends(get_session),
    ) -> TokenService:
        """Creates TokenService dependency instance.

        Args:
            session: Database session

        Returns:
            Configured TokenService instance
        """
        return TokenService(session, token_model, configuration)

    is_authenticated = dependency_overrides["is_authenticated"]
    is_owner = dependency_overrides["update_delete_get"]

    router = APIRouter(
        prefix="", tags=["users"], dependencies=[Depends(is_authenticated)]
    )
    public_router = APIRouter(prefix="/users", tags=["users"])
    service_user = Annotated[UserService, Depends(create_user_service_dep)]
    service_token_depends = Annotated[TokenService, Depends(create_token_service)]

    @router.get("/@me", response_model=UserPayloadSchema)
    async def read_users_me(
        service: service_token_depends, token: str = Depends(oauth2_scheme)
    ):
        """Gets current authenticated user's information from token.

        Args:
            service: Token service instance
            token: OAuth2 access token

        Returns:
            Current user payload data
        """
        return service.get_token_info(token)

    @public_router.post("/", response_model=user_read_schema)
    async def create_user(user: user_register_schema, service: service_user):  # type: ignore
        """Registers a new user.

        Args:
            user: User registration data
            service: User service instance

        Returns:
            Created user data
        """
        return await service.register(user)

    @router.put("/{_id}", status_code=204, dependencies=[Depends(is_owner)])
    async def update_user(
        _id: UUID,
        service: service_user,
        form_data: user_update_schema,  # type: ignore
    ):
        """Updates existing user data.

        Args:
            _id: User ID to update
            service: User service instance
            form_data: User update data
        """
        return await service.update_user(_id, form_data)

    @router.delete("/{_id}", status_code=204, dependencies=[Depends(is_owner)])
    async def delete_user(_id: UUID, service: service_user):
        """Deletes existing user.

        Args:
            _id: User ID to delete
            service: User service instance
        """
        return await service.delete_user(_id)

    @router.get(
        "/{_id}", response_model=user_read_schema, dependencies=[Depends(is_owner)]
    )
    async def get_user(_id: UUID, service: service_user):
        """Gets user by ID.

        Args:
            _id: User ID to retrieve
            service: User service instance

        Returns:
            User data
        """
        return await service.get_user(_id)

    public_router.include_router(router)
    return public_router
