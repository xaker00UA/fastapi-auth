from httpx import AsyncClient
from pydantic.v1.class_validators import Validator
from pydantic_core import ValidationError

from backauth.auth.schemas import GithubAssessToken, DiscordAssessToken, UserDiscord
from backauth.auth.service.auth_service import AuthService


class DiscordAuthService(AuthService[DiscordAssessToken]):
    service_name = "discord"
    model = DiscordAssessToken

    async def get_user(self, token: DiscordAssessToken):
        async with AsyncClient() as client:
            response = await client.get(
                "https://discord.com/api/v10/users/@me",
                headers={"Authorization": f"Bearer {token.access_token}"},
            )
            if response.status_code == 200:
                data = response.json()
                try:
                    return UserDiscord.model_validate(data)
                except ValidationError:
                    raise ValueError("Not email")
            raise Exception("Invalid token")

    async def get_token(self, code: str, state: str) -> DiscordAssessToken:
        service = await self.valid_state(state)
        query_params = {
            "code": code,
            "redirect_uri": self.conf.redirect_uri,
            **self.build_params_token(service),
        }
        async with AsyncClient() as client:
            response = await client.post(
                self._token_urls[self.service_name],
                data=query_params,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                auth=(self.conf[service].id, self.conf[service].secret),
            )
            if response.status_code == 200:
                data = response.json()
                token = self.model.model_validate(data)
                return token
            print(response.json())
            raise Exception("Invalid code", response.json())
