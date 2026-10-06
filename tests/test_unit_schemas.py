"""Tests unitarios de app/schemas.py (validación de datos de entrada y salida)."""

import pytest
from pydantic import ValidationError

from app.models import User, utcnow
from app.schemas import OTPVerify, UserRegister, UserResponse, UserUpdate

pytestmark = pytest.mark.unit


def test_register_normalizes_email_and_name():
    """El email se pasa a minúsculas y se quitan espacios del nombre."""
    data = UserRegister(email="Ana@Gmail.COM", password="Segura123", full_name="  Ana Pérez ")

    assert data.email == "ana@gmail.com"
    assert data.full_name == "Ana Pérez"


@pytest.mark.parametrize(
    "password",
    ["corta1", "SoloLetras", "12345678", "a1" * 40],
    ids=["muy-corta", "sin-numero", "sin-letra", "mas-de-72"],
)
def test_register_rejects_weak_password(password):
    """La contraseña debe tener 8-72 caracteres, con letras y números."""
    with pytest.raises(ValidationError):
        UserRegister(email="ana@gmail.com", password=password, full_name="Ana")


def test_register_rejects_invalid_email():
    """Un email con formato inválido no se acepta."""
    with pytest.raises(ValidationError):
        UserRegister(email="no-es-un-email", password="Segura123", full_name="Ana")


@pytest.mark.parametrize("code", ["12345", "1234567", "12a456", " 123456"])
def test_otp_must_be_six_digits(code):
    """El OTP debe ser exactamente 6 dígitos."""
    with pytest.raises(ValidationError):
        OTPVerify(email="ana@gmail.com", code=code)


def test_user_update_rules():
    """Debe enviarse al menos un campo y, para cambiar la contraseña, la actual."""
    with pytest.raises(ValidationError):
        UserUpdate()
    with pytest.raises(ValidationError):
        UserUpdate(new_password="NuevaClave1")

    assert UserUpdate(full_name="Ana María").full_name == "Ana María"
    assert UserUpdate(current_password="Segura123", new_password="NuevaClave1").new_password


def test_user_response_hides_password_hash():
    """La respuesta pública del usuario nunca incluye el hash de la contraseña."""
    user = User(id=1, email="ana@gmail.com", password_hash="HASH-SECRETO", full_name="Ana",
                created_at=utcnow(), updated_at=utcnow())

    data = UserResponse.model_validate(user).model_dump()
    assert "password_hash" not in data
    assert "HASH-SECRETO" not in str(data)
