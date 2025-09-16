from typing import TYPE_CHECKING

from pydantic import BaseModel, field_validator, field_serializer

if TYPE_CHECKING:
    from backauth.user.model import ScopeOrm


class UserLoginSchema(BaseModel):
    email: str
    password: str


class UserRegisterSchema(UserLoginSchema):
    username: str
    confirm_password: str

    @field_validator("confirm_password")
    def password_match(cls, v, values, **kwargs):
        if v != values["password"]:
            raise ValueError("Passwords do not match")
        return v


class UserUpdateSchema(BaseModel):
    username: str | None
    email: str | None
    first_name: str | None
    last_name: str | None


class UserResponseSchema(BaseModel):
    id: int
    username: str
    email: str
    first_name: str
    last_name: str
    is_active: bool
    is_superuser: bool
    scopes: list[str]
    oauth_provider: str
    oauth_id: str
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}

    @field_serializer("scopes", when_used="json")
    def serialize_scopes(self, scopes: list["ScopeOrm"], _info) -> list[str]:
        return [scope.name for scope in scopes]
