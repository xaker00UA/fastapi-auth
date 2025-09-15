from httpx import AsyncClient

from backauth.auth.schemas import GithubAssessToken
from backauth.auth.service.auth_service import AuthService


class GithubAuthService(AuthService[GithubAssessToken]):
    service_name = "github"
    model = GithubAssessToken

    async def get_user(self, token: GithubAssessToken):
        async with AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {token.access_token}"},
            )
            if response.status_code == 200:
                data = response.json()
                return data
            raise Exception("Invalid token")
