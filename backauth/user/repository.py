from typing import Any, Type
from uuid import UUID

from sqlalchemy import select, update, delete, Executable
from sqlalchemy.ext.asyncio import AsyncSession

from backauth.user.model import UserOrm


class UserRepository:
    session: AsyncSession
    model: type[UserOrm]
    def __init__(self, session: AsyncSession, model: Type[UserOrm]):
        self.session = session
        self.model = model

    async def _get_user(self, statement: Executable):
        result = await self.session.execute(statement)
        return result.unique().scalar_one_or_none()

    async def get_by_id(self, _id: UUID) -> UserOrm | None:
        stmt = select(self.model).where(self.model.id == _id)
        return await self._get_user(stmt)

    async def get_by_email(self, email: str) -> UserOrm | None:
        stmt = select(self.model).where(self.model.email == email)
        return await self._get_user(stmt)

    async def get_by_username(self, username: str) -> UserOrm | None:
        stmt = select(self.model).where(self.model.username == username)
        return await self._get_user(stmt)

    async def update(self, _id: UUID, data: dict[str, Any]) -> None:
        stmt = update(self.model).where(self.model.id == _id).values(**data)
        await self.session.execute(stmt)
        await self.session.commit()

    async def delete(self, _id: UUID) -> None:
        stmt = delete(self.model).where(self.model.id == _id)
        await self.session.execute(stmt)
        await self.session.commit()

    async def create(self, data: dict[str, Any]) -> UserOrm:
        user = self.model(**data)
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)
        return user
