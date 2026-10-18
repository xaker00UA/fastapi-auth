"""Google ID token claims and their binding to the OAuth access token."""

from datetime import UTC, datetime, timedelta

import pytest
from backauth.auth.schemas import GoogleAssessToken
from backauth.auth.service.google import GoogleAuthService
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError


@pytest.fixture(scope="module")
def google_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def google_service():
    return object.__new__(GoogleAuthService)


def google_token(key, *, include_at_hash=True, **claims):
    payload = {
        "sub": "123",
        "name": "Test User",
        "given_name": "Test",
        "family_name": "User",
        "picture": "https://example.com/avatar.png",
        "email": "test@example.com",
        "email_verified": True,
        "aud": "test-client",
        "iss": "https://accounts.google.com",
        "exp": datetime.now(UTC) + timedelta(minutes=5),
        **claims,
    }
    access_token = "google-access-token"
    return GoogleAssessToken(
        access_token=access_token,
        expires_in=300,
        id_token=jwt.encode(
            payload,
            key,
            algorithm="RS256",
            access_token=access_token if include_at_hash else None,
        ),
        refresh_token="google-refresh-token",
        scope="openid email profile",
        token_type="Bearer",
    )


@pytest.mark.parametrize("include_at_hash", [True, False])
async def test_google_user_with_optional_access_token_hash(
    google_service, google_key, include_at_hash
):
    token = google_token(google_key, include_at_hash=include_at_hash)

    user = await google_service.get_user(token)

    assert user.sub == "123"
    assert user.get_email() == "test@example.com"


async def test_google_user_rejects_mismatched_access_token(google_service, google_key):
    token = google_token(google_key)
    token.access_token = "different-access-token"

    with pytest.raises(JWTClaimsError, match="at_hash claim does not match"):
        await google_service.get_user(token)


async def test_google_user_rejects_expired_id_token(google_service, google_key):
    token = google_token(google_key, exp=datetime.now(UTC) - timedelta(minutes=1))

    with pytest.raises(ExpiredSignatureError):
        await google_service.get_user(token)


async def test_google_user_rejects_id_token_before_nbf(google_service, google_key):
    token = google_token(google_key, nbf=datetime.now(UTC) + timedelta(minutes=1))

    with pytest.raises(JWTClaimsError, match="not yet valid"):
        await google_service.get_user(token)
