"""
Modelos SQLAlchemy: cada clase es una tabla de la base de datos.

Tablas (sección 3.1 del enunciado):
- users:          datos de los usuarios registrados.
- otp_codes:      códigos OTP generados y su expiración.
- login_sessions: sesiones activas con su token JWT.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    """
    Devuelve la fecha y hora actual en UTC, sin zona horaria.

    SQLite no guarda la zona horaria, así que todas las fechas se manejan
    en UTC "sin zona" para poder compararlas sin errores
    (p. ej. `otp.expires_at < utcnow()`).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    """Usuario registrado en el sistema."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    # unique=True: la base de datos impide registrar dos veces el mismo email
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    # Nunca se guarda la contraseña en texto plano, solo su hash bcrypt
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(150), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    # onupdate: SQLAlchemy actualiza la fecha automáticamente cada vez que se modifica el usuario
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )

    # Relaciones: permiten hacer user.otp_codes y user.sessions.
    # cascade="all, delete-orphan": si se borra el usuario, se borran sus OTP y sesiones.
    otp_codes: Mapped[list["OTPCode"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    sessions: Mapped[list["LoginSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        """Texto para depuración; no incluye el hash de la contraseña."""
        return f"<User id={self.id} email={self.email!r}>"


class OTPCode(Base):
    """Código OTP de 6 dígitos enviado por correo, válido por tiempo limitado."""

    __tablename__ = "otp_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    code: Mapped[str] = mapped_column(String(6), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # Un OTP solo puede usarse una vez: al verificarlo se marca used=True
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    user: Mapped["User"] = relationship(back_populates="otp_codes")

    def is_valid(self) -> bool:
        """Indica si el código todavía se puede usar (no usado y no expirado)."""
        return not self.used and self.expires_at > utcnow()

    def __repr__(self) -> str:
        """Texto para depuración; no muestra el código para no exponerlo en logs."""
        return f"<OTPCode id={self.id} user_id={self.user_id} used={self.used}>"


class LoginSession(Base):
    """
    Sesión activa de un usuario, asociada a un token JWT.

    Un token solo es aceptado si existe aquí. Al cerrar sesión (logout)
    se borra la fila, y así el token queda revocado aunque no haya expirado.
    """

    __tablename__ = "login_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    token: Mapped[str] = mapped_column(String(512), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    user: Mapped["User"] = relationship(back_populates="sessions")

    def is_active(self) -> bool:
        """Indica si la sesión no ha expirado."""
        return self.expires_at > utcnow()

    def __repr__(self) -> str:
        """Texto para depuración; no muestra el token."""
        return f"<LoginSession id={self.id} user_id={self.user_id}>"
