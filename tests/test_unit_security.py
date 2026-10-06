"""Tests unitarios de app/security.py y app/middleware.py: bcrypt, JWT y rutas protegidas."""

from datetime import timedelta

import pytest
from jose import jwt

from app import config
from app.middleware import is_protected
from app.models import utcnow
from app.security import (
    TokenError,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)

pytestmark = pytest.mark.unit


def test_hash_password_uses_salt_and_verifies():
    """La misma contraseña produce hashes distintos (sal) y ambos se verifican."""
    h1 = hash_password("Segura123")
    h2 = hash_password("Segura123")

    assert h1 != h2
    assert h1.startswith("$2b$")  # formato bcrypt
    assert "Segura123" not in h1
    assert verify_password("Segura123", h1)
    assert verify_password("Segura123", h2)


def test_verify_password_rejects_wrong_or_invalid_hash():
    """Una contraseña incorrecta o un hash corrupto no se aceptan."""
    h = hash_password("Segura123")

    assert not verify_password("Incorrecta1", h)
    assert not verify_password("Segura123", "esto-no-es-un-hash")


def test_jwt_roundtrip_contains_expected_claims():
    """El token se decodifica al mismo usuario e incluye sub, iat, exp y jti."""
    token, expires_at = create_access_token(42)

    assert decode_access_token(token) == 42
    claims = jwt.get_unverified_claims(token)
    assert set(claims) == {"sub", "iat", "exp", "jti"}
    assert expires_at > utcnow()


def test_jwt_tokens_are_unique():
    """Dos tokens del mismo usuario nunca son iguales (gracias a jti)."""
    assert create_access_token(1)[0] != create_access_token(1)[0]


@pytest.mark.parametrize(
    "bad_token",
    [
        # Expirado hace 1 segundo
        jwt.encode({"sub": "1", "exp": utcnow() - timedelta(seconds=1)}, config.SECRET_KEY, algorithm="HS256"),
        # Firmado con otra clave
        jwt.encode({"sub": "1", "exp": utcnow() + timedelta(minutes=5)}, "otra-clave", algorithm="HS256"),
        # Algoritmo "none" (sin firma)
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.",
        # Sin claim "sub"
        jwt.encode({"exp": utcnow() + timedelta(minutes=5)}, config.SECRET_KEY, algorithm="HS256"),
        # Texto que no es un JWT
        "basura",
    ],
    ids=["expirado", "otra-clave", "alg-none", "sin-sub", "basura"],
)
def test_invalid_jwt_is_rejected(bad_token):
    """Tokens expirados, falsificados o mal formados lanzan TokenError."""
    with pytest.raises(TokenError):
        decode_access_token(bad_token)


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/users/profile", True),
        ("/auth/logout", True),
        ("/auth/refresh", True),
        ("/auth/login", False),
        ("/auth/register", False),
        ("/auth/verify-otp", False),
        ("/docs", False),
        ("/usersx", False),
    ],
)
def test_protected_paths(path, expected):
    """El middleware solo exige token en las rutas marcadas como protegidas."""
    assert is_protected(path) is expected
