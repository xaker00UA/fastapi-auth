from datetime import timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jose import JWTError, jwt
from pydantic import ValidationError

from backauth.auth.service.token_service import TokenService
from backauth.config.setting import Config, TokenSettings


@pytest.fixture(params=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"])
def service(request, tmp_path):
    algorithm = request.param
    if algorithm.startswith("RS"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        curve = {"ES256": ec.SECP256R1, "ES384": ec.SECP384R1, "ES512": ec.SECP521R1}[
            algorithm
        ]
        key = ec.generate_private_key(curve())
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    settings = TokenSettings(
        algorithm=algorithm, private_key_path=str(private), public_key_path=str(public)
    )
    instance = object.__new__(TokenService)
    instance.conf = SimpleNamespace(token=settings)

    async def get(key):
        return None

    instance.redis = SimpleNamespace(get=get)
    return instance


async def test_access_token_sign_verify_and_blacklist(service):
    token = service.create_access_token({"user_id": "42"})
    assert jwt.get_unverified_header(token)["alg"] == service.conf.token.algorithm
    assert service.get_token_info(token)["user_id"] == "42"
    assert await service.validate_token(token)

    async def blocked(key):
        return b"block"

    service.redis.get = blocked
    assert not await service.validate_token(token)


async def test_expired_tokens_are_rejected(service):
    token = service.create_access_token(
        {"user_id": "42"}, expires_delta=timedelta(seconds=-1)
    )
    assert not await service.validate_token(token)
    with pytest.raises(JWTError):
        service.get_token_info(token)


async def test_tampering_and_algorithm_confusion_are_rejected(service):
    token = service.create_access_token({"user_id": "42"})
    head, _, signature = token.split(".")
    payload = jwt.encode({"user_id": "attacker"}, "secret", algorithm="HS256").split(
        "."
    )[1]
    assert not await service.validate_token(f"{head}.{payload}.{signature}")
    forged = jwt.encode(
        {"user_id": "attacker", "exp": 4102444800}, "secret", algorithm="HS256"
    )
    assert not await service.validate_token(forged)
    assert not await service.validate_token("not-a-token")


async def test_tokens_without_expiry_are_rejected(service):
    token = jwt.encode(
        {"user_id": "42"},
        service.conf.token.private_key,
        algorithm=service.conf.token.algorithm,
    )
    assert not await service.validate_token(token)


def test_key_objects_are_cached(service):
    assert service.conf.token.private_key is service.conf.token.private_key
    assert service.conf.token.public_key is service.conf.token.public_key


def test_nested_environment_selects_algorithm(monkeypatch):
    monkeypatch.setenv("TOKEN__ALGORITHM", "ES384")
    # Redis is never contacted by settings validation.
    from redis.asyncio import ConnectionPool

    config = Config(
        redirect_uri="https://example.com/callback",
        redis_connection_pool=ConnectionPool(),
        _env_file=None,
    )
    assert config.token.algorithm == "ES384"


@pytest.mark.parametrize("algorithm", ["none", "HS256", "invalid"])
def test_unsupported_algorithms_fail_at_configuration(algorithm):
    with pytest.raises(ValidationError):
        TokenSettings(algorithm=algorithm)


def test_incorrect_ecc_curve_is_rejected(service):
    if service.conf.token.algorithm != "ES256":
        pytest.skip("P-256 case only")
    service.conf.token.algorithm = "ES384"
    with pytest.raises(ValueError, match="ECC key"):
        _ = service.conf.token.private_key


async def test_google_identity_claims_keep_expiry_checks():
    from backauth.auth.service.google import GoogleAuthService

    instance = object.__new__(GoogleAuthService)
    expired = jwt.encode({"exp": 1}, "google-test", algorithm="HS256")
    with pytest.raises(JWTError):
        await instance.get_user(
            SimpleNamespace(id_token=expired, access_token="google-access-token")
        )
