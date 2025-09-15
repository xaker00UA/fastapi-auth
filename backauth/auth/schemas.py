
from pydantic import BaseModel

class UserType(BaseModel):
    def get_username(self):...
    def get_email(self):...


class TokenType(BaseModel):
    def get_access_token(self):...
    def get_refresh_token(self):...

class GoogleAssessToken(TokenType):
    access_token: str
    expires_in: int
    id_token: str
    refresh_token: str
    scope: str
    token_type: str

    def get_access_token(self):
        return self.access_token
    def get_refresh_token(self):
        return self.refresh_token


class GithubAssessToken(TokenType):
    access_token: str
    refresh_token: str
    refresh_token_expires_in: int
    scope: str
    token_type: str

    def get_access_token(self):
        return self.access_token
    def get_refresh_token(self):
        return self.refresh_token

class UserGoogle(UserType):
    sub: str
    name: str
    given_name: str
    family_name: str
    picture: str
    email: str
    email_verified: bool

    def get_email(self):
        return self.email
    def get_username(self):
        return self.given_name




class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"


