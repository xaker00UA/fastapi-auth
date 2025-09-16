import json

from httpx import AsyncClient
from pydantic import ValidationError

from backauth.auth.schemas import GithubAssessToken, UserGithub
from backauth.auth.service.auth_service import AuthService


class GithubAuthService(AuthService[GithubAssessToken]):
    service_name = "github"
    model = GithubAssessToken

    async def get_user(self, token: GithubAssessToken):
        async with AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {token.access_token}"},
            )
            if response.status_code == 200:
                data = response.json()
                try:
                    return UserGithub.model_validate(data)
                except ValidationError:
                    try:
                        emails = await self.get_email(token)
                        data.update({"email": emails})
                        return UserGithub.model_validate(data)
                    except ValidationError:
                        raise ValueError("Not email")

            raise Exception("Invalid token")

    async def get_email(self, token: GithubAssessToken) -> str:
        async with AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {token.access_token}"},
            )
            if response.status_code == 200:
                data = response.json()
                return next(filter(lambda x: x.get("primary") is True, data), {}).get(
                    "email", ""
                )
            raise Exception("Invalid token")
