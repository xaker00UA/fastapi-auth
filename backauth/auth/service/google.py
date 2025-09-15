from jwt import JWT
from backauth.auth.schemas import GoogleAssessToken, UserGoogle
from backauth.auth.service.auth_service import AuthService

jwt_instance = JWT()
decode = jwt_instance.decode


class GoogleAuthService(AuthService[GoogleAssessToken]):
    service_name = "google"
    model = GoogleAssessToken

    async def get_user(self, token: GoogleAssessToken):
        user = decode(token.id_token, do_verify=False)
        return UserGoogle.model_validate(user)
