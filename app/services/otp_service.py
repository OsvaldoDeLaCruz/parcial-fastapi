"""
Servicio OTP: generación y verificación de códigos de un solo uso.

Reglas:
- El código tiene 6 dígitos y se genera con PyOTP.
- Es válido por OTP_EXPIRE_MINUTES (máximo 15 minutos) desde que se crea.
- Solo se puede usar una vez.
- Al generar un código nuevo, los anteriores del mismo usuario se invalidan,
  así solo existe un código válido a la vez.
"""

import hmac
from datetime import timedelta

import pyotp
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import OTP_EXPIRE_MINUTES, OTP_RESEND_COOLDOWN_SECONDS
from app.models import OTPCode, User, utcnow

OTP_DIGITS = 6


def generate_otp_code() -> str:
    """
    Genera un código numérico aleatorio de 6 dígitos con PyOTP.

    Se crea un secreto aleatorio nuevo (pyotp.random_base32 usa el módulo
    `secrets`, criptográficamente seguro) y a partir de él un código HOTP.
    Como el secreto es distinto cada vez, el código no se puede predecir.
    La expiración no depende de PyOTP: se controla con `expires_at` en la BD.
    """
    secret = pyotp.random_base32()
    return pyotp.HOTP(secret, digits=OTP_DIGITS).at(0)


def invalidate_user_otps(db: Session, user: User) -> None:
    """Marca como usados todos los códigos pendientes del usuario."""
    db.execute(
        update(OTPCode)
        .where(OTPCode.user_id == user.id, OTPCode.used.is_(False))
        .values(used=True)
    )


def create_otp(db: Session, user: User) -> str:
    """
    Crea un OTP nuevo para el usuario, lo guarda en la BD y devuelve el código.

    Antes invalida los códigos anteriores para que solo el último sea válido.
    El código devuelto se debe enviar por correo; nunca se devuelve en la API.
    """
    invalidate_user_otps(db, user)

    code = generate_otp_code()
    otp = OTPCode(
        user_id=user.id,
        code=code,
        expires_at=utcnow() + timedelta(minutes=OTP_EXPIRE_MINUTES),
    )
    db.add(otp)
    db.commit()
    return code


def verify_otp(db: Session, user: User, code: str) -> bool:
    """
    Verifica el código enviado por el usuario.

    Devuelve True solo si existe un código del usuario que coincida,
    no esté usado y no haya expirado. Si es correcto, se marca como usado
    para que no pueda reutilizarse.
    """
    pending = db.scalars(
        select(OTPCode).where(
            OTPCode.user_id == user.id,
            OTPCode.used.is_(False),
            OTPCode.expires_at > utcnow(),
        )
    ).all()

    for otp in pending:
        # compare_digest compara en tiempo constante: evita que un atacante
        # deduzca dígitos midiendo cuánto tarda la comparación (timing attack)
        if hmac.compare_digest(otp.code, code):
            otp.used = True
            db.commit()
            return True
    return False


def has_pending_login(db: Session, user: User) -> bool:
    """
    Indica si el usuario tiene un inicio de sesión en curso.

    Es decir, si se le generó un OTP en los últimos OTP_EXPIRE_MINUTES
    (eso solo ocurre después de un login con contraseña correcta).
    Se usa en /auth/resend-otp para que nadie pueda pedir códigos para un
    usuario sin haber pasado antes por la contraseña.
    """
    last_created = db.scalar(
        select(OTPCode.created_at)
        .where(OTPCode.user_id == user.id)
        .order_by(OTPCode.created_at.desc())
        .limit(1)
    )
    return last_created is not None and last_created > utcnow() - timedelta(
        minutes=OTP_EXPIRE_MINUTES
    )


def seconds_until_resend(db: Session, user: User) -> int:
    """
    Indica cuántos segundos faltan para poder pedir otro OTP.

    Devuelve 0 si ya se puede reenviar. Evita que se abuse del endpoint
    /auth/resend-otp para enviar muchos correos seguidos.
    """
    last_created = db.scalar(
        select(OTPCode.created_at)
        .where(OTPCode.user_id == user.id)
        .order_by(OTPCode.created_at.desc())
        .limit(1)
    )
    if last_created is None:
        return 0

    elapsed = (utcnow() - last_created).total_seconds()
    return max(0, int(OTP_RESEND_COOLDOWN_SECONDS - elapsed))
