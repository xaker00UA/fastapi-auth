from datetime import datetime
from typing import Optional, TYPE_CHECKING, Sequence
from uuid import UUID, uuid4

from sqlalchemy import (
    String,
    DateTime,
    Boolean,
    ForeignKey,
    UniqueConstraint,
    LargeBinary,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from bcrypt import hashpw, gensalt, checkpw


class UserScopeOrm:
    __tablename__ = "user_scope"
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), primary_key=True)
    scope_id: Mapped[UUID] = mapped_column(ForeignKey("scopes.id"), primary_key=True)
    __table_args__ = (UniqueConstraint("user_id", "scope_id", name="user_scope_uc"),)


class ScopeOrm:
    __tablename__ = "scopes"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)


class UserOrm:
    if TYPE_CHECKING:
        scopes: Mapped[Sequence["ScopeOrm"]] = relationship(
            secondary="user_scope", lazy="joined"
        )
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    hashed_password: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)

    first_name: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    last_name: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)

    oauth_provider: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    oauth_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.now(), onupdate=datetime.now(), nullable=False
    )

    def is_valid_password(self, password: str) -> bool:
        if not self.hashed_password:
            return False
        return checkpw(password.encode(), self.hashed_password)

    def set_password(self, password: str) -> None:
        salt = gensalt()
        hashed = hashpw(password.encode(), salt)
        self.hashed_password = hashed
