from typing import Any, Type
from uuid import UUID

from sqlalchemy import delete, select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from backauth.auth.model.token import TokenOrm


class TokenRepository:
    session: AsyncSession
    model: type[TokenOrm]

    def __init__(self, session: AsyncSession, model: Type[TokenOrm]):
        self.session = session
        self.model = model

    async def create(self, data: dict[str, Any]) -> TokenOrm:
        token = self.model(**data)
        self.session.add(token)
        await self.session.commit()
        await self.session.refresh(token)
        return token

    async def delete(self, _id: UUID) -> None:
        stmt = delete(self.model).where(self.model.id == _id)
        await self.session.execute(stmt)
        await self.session.commit()

    async def get_by_id(self, _id: UUID) -> TokenOrm | None:
        stmt = select(self.model).where(
            and_(self.model.id == _id, self.model.is_full_block == False)
        )
        result = await self.session.execute(stmt)
        return result.unique().scalar_one_or_none()

    async def get_by_sub(self, sub: UUID) -> list[TokenOrm]:
        stmt = select(self.model).where(self.model.subject == sub)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def delete_by_sub(self, sub: UUID) -> None:
        stmt = delete(self.model).where(self.model.subject == sub)
        await self.session.execute(stmt)
        await self.session.commit()

    async def get_by_refresh_token(self, refresh_token: str) -> TokenOrm | None:
        stmt = select(self.model).where(self.model.refresh_token == refresh_token)
        result = await self.session.execute(stmt)
        return result.unique().scalar_one_or_none()

    async def block(self, subject: UUID) -> list[TokenOrm]:
        tokens = await self.get_by_sub(subject)
        for token in tokens:
            token.is_blocked_access = True
            await self.session.commit()
        return tokens

    async def full_block(self, subject: UUID) -> list[TokenOrm]:
        tokens = await self.get_by_sub(subject)
        for token in tokens:
            token.is_full_block = True
            token.is_blocked_access = True
            await self.session.commit()
        return tokens
