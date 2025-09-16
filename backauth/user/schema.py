from typing import TYPE_CHECKING

from pydantic import BaseModel, field_validator, field_serializer, model_validator

if TYPE_CHECKING:
    from backauth.user.model import ScopeOrm


class UserLoginSchema(BaseModel):
    email: str
    password: str


class UserRegisterSchema(UserLoginSchema):
    username: str
    confirm_password: str

    @model_validator(mode="after")
    def check_passwords_match(self) -> "UserRegisterSchema":
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


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
