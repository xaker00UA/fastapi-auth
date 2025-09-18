from typing import Type
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backauth.auth.model.token import TokenOrm
from backauth.auth.schemas import Token
from backauth.auth.service.auth_service import AuthService
from backauth.auth.service.token_service import TokenService
from backauth.config.setting import Config
from backauth.user.model import UserOrm
from backauth.user.repository import UserRepository
from backauth.user.schema import UserLoginSchema, UserRegisterSchema, UserUpdateSchema


class UserService:

    def __init__(
        self,
        db: AsyncSession,
        user_model: Type[UserOrm],
        token_model: Type[TokenOrm],
        configuration: Config,
    ) -> None:
        self.conf = configuration
        self.user_repository = UserRepository(db, user_model)
        self.token_service = TokenService(db, token_model, configuration)
        self.db = db
        self.token_model = token_model

    async def create_user_from_oauth(self, code: str, state: str) -> Token:
        auth_service = await AuthService(
            self.db, self.token_model, self.conf
        ).get_service_by_state(state)
        token = await auth_service.get_token(code, state)
        user_data = await auth_service.get_user(token)
        user = await self.user_repository.get_by_email(user_data.get_email())
        username = await self.user_repository.get_by_username(user_data.get_username())
        if user or username:
            raise ValueError("Email or username already exists")
        entity = await self.user_repository.create(user_data.get_orn_dict())
        return await self.token_service.get_token(entity)

    async def login(self, user_login: UserLoginSchema) -> Token:
        user = await self.user_repository.get_by_email(user_login.email)
        if not user:
            raise ValueError("Invalid email")
        if not user.is_valid_password(user_login.password):
            raise ValueError("Invalid password")
        return await self.token_service.get_token(user)

    async def register(self, user_register: UserRegisterSchema):
        user = await self.user_repository.get_by_email(user_register.email)
        username = await self.user_repository.get_by_username(user_register.username)
        if user or username:
            raise ValueError("Email or username already exists")
        return await self.user_repository.create(
            user_register.model_dump(exclude={"confirm_password"})
        )

    async def delete_user(self, user_id: UUID):
        await self.user_repository.delete(user_id)

    async def get_user(self, user_id: UUID) -> UserOrm:
        result = await self.user_repository.get_by_id(user_id)
        if not result:
            raise ValueError("User not found")
        return result

    async def update_user(self, user_id: UUID, data: UserUpdateSchema) -> None:
        user, username = None, None
        if data.email:
            user = await self.user_repository.get_by_email(data.email)
        if data.username:
            username = await self.user_repository.get_by_username(data.username)
        if user or username:
            raise ValueError("Email or username already exists")
        await self.user_repository.update(user_id, data.model_dump(exclude_none=True))
        await self.token_service.blacklist_access_token(user_id)

    async def get_token_by_refresh(self, refresh_token: str) -> Token:
        subject = await self.token_service.get_info_from_refresh(refresh_token)
        user = await self.user_repository.get_by_id(subject.subject)
        if not user:
            raise ValueError("Invalid refresh token")
        return await self.token_service.create_access_token_by_refresh(
            refresh_token, user
        )

    def get_auth_url(self, service: str) -> str:
        auth_service = AuthService(self.db, self.token_model, self.conf).get_service(
            service
        )
        return auth_service.get_auth_url(service)

    def get_token_service(self):
        return self.token_service
