from datetime import datetime
from uuid import UUID

from sqlalchemy.orm import Mapped, mapped_column


class TokenOrm:
    __tablename__="tokens"

    id :Mapped[UUID]=mapped_column(init=True,primary_key=True)
    subject:Mapped[UUID]=mapped_column(index=True)
    refresh_token:Mapped[str]
    expires_at:Mapped[int]
    issued_at:Mapped[int]=mapped_column(default=int(datetime.now().timestamp()))
    is_blocked_access:Mapped[bool]=mapped_column(default=False)
    is_full_block:Mapped[bool]=mapped_column(default=False)