from pydantic import BaseModel


class UserType(BaseModel):
    def get_username(self):
        raise NotImplementedError

    def get_email(self):
        raise NotImplementedError

    def get_orn_dict(self):
        data = {
            "email": self.get_email(),
            "username": self.get_username(),
        }

        if hasattr(self, "first_name"):
            data["first_name"] = self.first_name

        if hasattr(self, "last_name"):
            data["last_name"] = self.last_name

        return data


class TokenType(BaseModel):
    def get_access_token(self): ...
    def get_refresh_token(self): ...


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
    scope: str
    token_type: str

    def get_access_token(self):
        return self.access_token

    def get_refresh_token(self):
        return self.refresh_token


class DiscordAssessToken(TokenType):
    access_token: str
    expires_in: int
    refresh_token: str
    scope: str
    token_type: str


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


class UserGithub(UserType):
    login: str
    email: str
    name: str | None

    @property
    def first_name(self):
        return self.name

    def get_email(self):
        return self.email

    def get_username(self):
        return self.login


class UserDiscord(UserType):
    id: str
    username: str
    email: str
    avatar: str
    locale: str
    mfa_enabled: bool
    verified: bool
    global_name: str

    def get_email(self):
        return self.email

    def get_username(self):
        return self.username


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
