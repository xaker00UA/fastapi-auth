import asyncio
import random
import string
import uuid
from datetime import datetime, timedelta, UTC
from typing import Optional, Type

from jwt import JWT
from jwt.exceptions import JWTDecodeError as JWTError

from sqlalchemy.ext.asyncio import AsyncSession

from backauth.auth.model.token import TokenOrm
from backauth.auth.repository.tokenrepository import TokenRepository
from backauth.auth.schemas import Token
from backauth.config.setting import Config
from backauth.user.model import UserOrm
from redis.asyncio import Redis

jwt_instance = JWT()
encode = jwt_instance.encode
decode = jwt_instance.decode


class TokenService:
    ACCESS_TOKEN_TYPE = "access"
    REFRESH_TOKEN_TYPE = "refresh"

    def __init__(
        self,
        db: AsyncSession,
        token_model: Type[TokenOrm],
        configuration: Config,
    ):
        self.conf = configuration
        self.token_repository = TokenRepository(db, token_model)
        self.redis = Redis.from_url(self.conf.redis)

    async def get_token_by_oauth(self): ...
    async def get_token(self, user: UserOrm) -> Token:
        payload = await self.get_payload(user)
        _id = uuid.uuid4()
        access_token = self.create_access_token(payload, _id)
        refresh_token = await self.create_refresh_token(_id, payload)
        return Token(access_token=access_token, refresh_token=refresh_token)

    def create_access_token(
        self,
        data: dict,
        jti: uuid.UUID | None = None,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(UTC) + expires_delta
        else:
            expire = datetime.now(UTC) + timedelta(
                minutes=self.conf.token.access_token_expire_minutes
            )
        to_encode.update(
            {
                "iat": int(datetime.now(UTC).timestamp()),
                "exp": int(expire.timestamp()),
                "type": self.ACCESS_TOKEN_TYPE,
                "jti": str(jti) or str(uuid.uuid4()),
            }
        )
        encoded_jwt = encode(
            to_encode, self.conf.token.private_key, alg=self.conf.token.algorithm
        )
        return encoded_jwt

    async def create_refresh_token(
        self, jti: uuid.UUID, data: dict, expires_delta: Optional[timedelta] = None
    ) -> str:
        if expires_delta:
            expire = datetime.now(UTC) + expires_delta
        else:
            expire = datetime.now(UTC) + timedelta(
                days=self.conf.token.refresh_token_expire_days
            )
        res = await self.token_repository.create(
            {
                "id": jti,
                "subject": str(data["user_id"]),
                "refresh_token": self.generate_random_string(),
                "expires_at": expire.timestamp(),
            }
        )

        return res.refresh_token

    async def create_access_token_by_refresh(
        self, refresh_token: str, user: UserOrm
    ) -> Token:
        token_entity = await self.get_info_from_refresh(refresh_token)
        await self.token_repository.unblock(refresh_token)
        payload = await self.get_payload(user)
        exp = timedelta(seconds=token_entity.expires_at) - timedelta(
            seconds=datetime.now(UTC).timestamp()
        )

        _id = uuid.uuid4()
        access_token = self.create_access_token(payload, jti=_id)
        new_refresh_token = await self.create_refresh_token(
            _id, payload, expires_delta=exp
        )
        return Token(access_token=access_token, refresh_token=new_refresh_token)

    async def validate_token(self, token: str) -> bool:
        try:

            payload = decode(
                token,
                self.conf.token.public_key,
            )
            if await self.is_token_blacklisted(payload.get("jti", "")):
                return False
            return True

        except JWTError:
            return False

    def get_token_info(self, token: str) -> dict:
        payload = decode(
            token,
            self.conf.token.public_key,
            do_verify=True,
        )
        return payload

    async def get_info_from_refresh(self, refresh_token: str) -> TokenOrm:
        token_entity = await self.token_repository.get_by_refresh_token(refresh_token)
        if not token_entity or token_entity.expires_at > datetime.now(UTC).timestamp():
            raise ValueError("Invalid refresh token")
        return token_entity

    @staticmethod
    async def get_payload(user: UserOrm) -> dict:
        payload = {
            "user_id": str(user.id),
            "scopes": user.scopes,
            "email": user.email,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
        }
        return payload

    async def blacklist_access_token(self, subject: uuid.UUID):
        tokens = await self.token_repository.block(subject)
        task = []
        for token in tokens:
            task.append(
                self.redis.set(
                    f"token:{token.id}",
                    "block",
                    ex=self.conf.token.access_token_expire_minutes * 60,
                )
            )
        await asyncio.gather(*task)

    async def blacklist_refresh_token(self, subject: uuid.UUID):
        tokens = await self.token_repository.full_block(subject)
        task = []
        for token in tokens:
            task.append(
                self.redis.set(
                    f"token:{token.id}",
                    "block",
                    ex=self.conf.token.access_token_expire_minutes * 60,
                )
            )
        await asyncio.gather(*task)

    async def is_token_blacklisted(self, _id: str) -> bool:  # type: ignore
        res = await self.redis.get(f"token:{_id}")
        if res:
            return True
        return False

    @staticmethod
    def generate_random_string(length: int = 128) -> str:
        charset = string.ascii_letters + string.digits
        return "".join(random.choice(charset) for _ in range(length))
