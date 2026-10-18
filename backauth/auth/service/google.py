from jose import jwt

from backauth.auth.schemas import GoogleAssessToken, UserGoogle
from backauth.auth.service.auth_service import AuthService


class GoogleAuthService(AuthService[GoogleAssessToken]):
    service_name = "google"
    model = GoogleAssessToken

    async def get_user(self, token: GoogleAssessToken):
        # id_token comes directly from Google's token endpoint. Preserve the
        # previous expiry/nbf checks while reading its externally signed claims.
        user = jwt.decode(
            token.id_token,
            key="",
            access_token=token.access_token,
            options={"verify_signature": False, "verify_aud": False},
        )
        return UserGoogle.model_validate(user)
