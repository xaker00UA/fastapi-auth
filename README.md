# Backauth

FastAPI authentication with configurable JWT signatures.

## Signing algorithms

Install dependencies with `poetry install`. `python-jose[cryptography]` supports
RSA (`RS256`, `RS384`, `RS512`) and ECDSA (`ES256`, `ES384`, `ES512`).
The library keeps `RS256` as the default for existing consumers. Set the
algorithm explicitly in the application's environment or `.env`:

```dotenv
TOKEN__ALGORITHM=ES256
TOKEN__PRIVATE_KEY_PATH=/run/secrets/auth_private_key
TOKEN__PUBLIC_KEY_PATH=/run/secrets/auth_public_key
```

ECDSA requires the matching curve: P-256 for ES256, P-384 for ES384,
and P-521 for ES512. Keys use PEM format; private keys use PKCS8 and public
keys use SubjectPublicKeyInfo. Key files are parsed once per process to
avoid parsing them on every request. Restart consumers after rotating keys.

Create an ES256 pair outside your image and repository:

```bash
umask 077
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
```

Mount these files read-only at runtime. Each deployment must use its own
private key. Replacing an RSA pair with an ECC pair invalidates access tokens
signed with the old pair. Existing refresh tokens remain subject to their
normal storage, expiration and revocation rules.

Signature verification only allows the configured algorithm and requires an
expiration claim. Invalid, expired and incorrectly signed tokens are rejected.
OAuth state tokens use the same configured signing settings.

## Tests

```bash
poetry run pytest tests -q
```
