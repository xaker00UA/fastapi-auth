class AuthBackendException(Exception): ...


class GoogleException(AuthBackendException): ...


class DiscordException(AuthBackendException): ...


class FacebookException(AuthBackendException): ...


class TelegramException(AuthBackendException): ...


class GithubException(AuthBackendException): ...


class ClientNotFound(GoogleException): ...


class ClientSecretNotFound(GoogleException): ...


class EmailOrUsernameExist(AuthBackendException):
    def __init__(self):
        super().__init__("Email or Username already exist")


class InvalidEmailOrPassword(AuthBackendException):
    def __init__(self):
        super().__init__("Invalid email or password")


class UserNotFound(AuthBackendException): ...


class InvalidToken(AuthBackendException): ...
