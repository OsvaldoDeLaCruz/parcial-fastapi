"""
Esquemas Pydantic: definen y validan los datos que entran y salen de la API.

- Esquemas de entrada (lo que envía el cliente): si los datos no cumplen las
  reglas, FastAPI responde automáticamente 422 con el detalle del error.
- Esquemas de salida (lo que responde la API): controlan qué campos se
  exponen. Por ejemplo, UserResponse nunca incluye password_hash.

Los `examples` aparecen en la documentación automática (/docs).
"""

import re
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

# bcrypt solo usa los primeros 72 bytes de la contraseña; se limita para evitar
# que dos contraseñas distintas con el mismo inicio produzcan el mismo hash.
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 72


def validate_password_strength(password: str) -> str:
    """
    Verifica que la contraseña tenga al menos una letra y un número.

    La longitud mínima y máxima se valida con Field(min_length, max_length).
    Lanza ValueError (que Pydantic convierte en error 422) si no cumple.
    """
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ValueError("La contraseña debe contener al menos una letra y un número")
    if len(password.encode("utf-8")) > PASSWORD_MAX_LENGTH:
        raise ValueError(f"La contraseña no puede superar {PASSWORD_MAX_LENGTH} bytes")
    return password


class EmailNormalizedMixin(BaseModel):
    """Convierte el email a minúsculas para que 'Ana@Mail.com' y 'ana@mail.com' sean el mismo usuario."""

    @field_validator("email", mode="after", check_fields=False)
    @classmethod
    def normalize_email(cls, value: str) -> str:
        """Quita espacios y pasa el email a minúsculas antes de usarlo."""
        return value.strip().lower()


# ---------------------------------------------------------------------------
# Esquemas de entrada
# ---------------------------------------------------------------------------


class UserRegister(EmailNormalizedMixin):
    """Datos para registrar un usuario nuevo (POST /auth/register)."""

    email: EmailStr = Field(..., examples=["ana.perez@gmail.com"])
    password: str = Field(
        ...,
        min_length=PASSWORD_MIN_LENGTH,
        max_length=PASSWORD_MAX_LENGTH,
        examples=["Segura123"],
        description="Mínimo 8 caracteres, con al menos una letra y un número",
    )
    full_name: str = Field(..., min_length=2, max_length=150, examples=["Ana Pérez"])

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str) -> str:
        """Exige que la contraseña tenga al menos una letra y un número."""
        return validate_password_strength(value)

    @field_validator("full_name")
    @classmethod
    def strip_full_name(cls, value: str) -> str:
        """Quita espacios al inicio y al final; rechaza nombres que queden con menos de 2 letras."""
        value = value.strip()
        if len(value) < 2:
            raise ValueError("El nombre debe tener al menos 2 caracteres")
        return value


class UserLogin(EmailNormalizedMixin):
    """Credenciales para iniciar sesión (POST /auth/login). Si son correctas se envía un OTP."""

    email: EmailStr = Field(..., examples=["ana.perez@gmail.com"])
    password: str = Field(..., min_length=1, max_length=PASSWORD_MAX_LENGTH, examples=["Segura123"])


class OTPVerify(EmailNormalizedMixin):
    """Código OTP recibido por correo para completar el login (POST /auth/verify-otp)."""

    email: EmailStr = Field(..., examples=["ana.perez@gmail.com"])
    # pattern: exactamente 6 dígitos (ni letras, ni espacios)
    code: str = Field(..., pattern=r"^\d{6}$", examples=["482913"])


class OTPResend(EmailNormalizedMixin):
    """Solicitud para reenviar un código OTP (POST /auth/resend-otp)."""

    email: EmailStr = Field(..., examples=["ana.perez@gmail.com"])


class UserUpdate(BaseModel):
    """
    Campos que el usuario puede modificar de su perfil (PUT /users/profile).

    Todos son opcionales, pero debe enviarse al menos uno. Para cambiar la
    contraseña es obligatorio enviar también la contraseña actual.
    """

    full_name: Optional[str] = Field(None, min_length=2, max_length=150, examples=["Ana María Pérez"])
    current_password: Optional[str] = Field(
        None, max_length=PASSWORD_MAX_LENGTH, examples=["Segura123"]
    )
    new_password: Optional[str] = Field(
        None,
        min_length=PASSWORD_MIN_LENGTH,
        max_length=PASSWORD_MAX_LENGTH,
        examples=["NuevaClave456"],
    )

    @field_validator("full_name")
    @classmethod
    def strip_full_name(cls, value: Optional[str]) -> Optional[str]:
        """Igual que en el registro, pero el nombre es opcional (None = no se cambia)."""
        if value is None:
            return value
        value = value.strip()
        if len(value) < 2:
            raise ValueError("El nombre debe tener al menos 2 caracteres")
        return value

    @field_validator("new_password")
    @classmethod
    def check_new_password(cls, value: Optional[str]) -> Optional[str]:
        """Si se envía una contraseña nueva, debe cumplir la misma política que en el registro."""
        return value if value is None else validate_password_strength(value)

    @model_validator(mode="after")
    def check_fields(self) -> "UserUpdate":
        """Valida reglas que involucran varios campos a la vez."""
        if self.full_name is None and self.new_password is None:
            raise ValueError("Debe enviar al menos un campo para actualizar (full_name o new_password)")
        if self.new_password is not None and not self.current_password:
            raise ValueError("Para cambiar la contraseña debe enviar current_password")
        return self


# ---------------------------------------------------------------------------
# Esquemas de salida
# ---------------------------------------------------------------------------


class UserResponse(BaseModel):
    """Datos públicos de un usuario. No incluye password_hash."""

    # from_attributes: permite construir el esquema directamente desde un modelo SQLAlchemy
    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "examples": [
                {
                    "id": 1,
                    "email": "ana.perez@gmail.com",
                    "full_name": "Ana Pérez",
                    "created_at": "2026-10-06T14:30:00",
                    "updated_at": "2026-10-06T14:30:00",
                }
            ]
        },
    )

    id: int
    email: EmailStr
    full_name: str
    created_at: datetime
    updated_at: datetime


class TokenResponse(BaseModel):
    """Token JWT entregado tras verificar el OTP o refrescar la sesión."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "token_type": "bearer",
                    "expires_in": 1800,
                }
            ]
        }
    )

    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Segundos hasta que el token expire")


class MessageResponse(BaseModel):
    """Respuesta simple con un mensaje (registro, login, logout, reenvío de OTP)."""

    model_config = ConfigDict(
        json_schema_extra={"examples": [{"message": "Se envió un código de verificación a su correo"}]}
    )

    message: str
