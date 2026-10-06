"""
Funciones de seguridad: hash de contraseñas (bcrypt), tokens JWT y sesiones.

Flujo de un token:
1. Tras verificar el OTP se llama a create_session(): se genera el JWT y se
   guarda en la tabla login_sessions.
2. En cada petición protegida, el middleware valida la firma y expiración del
   JWT y además comprueba que su sesión siga existiendo en la BD.
3. En logout se llama a revoke_session(): se borra la sesión y el token deja
   de ser aceptado aunque todavía no haya expirado.
"""

import uuid
from datetime import datetime, timedelta

import bcrypt
from jose import JWTError, jwt
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app import config
from app.models import LoginSession, User, utcnow

# ---------------------------------------------------------------------------
# Contraseñas
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    """
    Genera el hash bcrypt de una contraseña.

    bcrypt agrega una "sal" aleatoria (gensalt), por eso la misma contraseña
    produce un hash distinto cada vez. Además es lento a propósito, lo que
    hace muy costoso probar millones de contraseñas si se roba la base de datos.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Comprueba si la contraseña corresponde al hash guardado."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        # Hash con formato inválido o contraseña de más de 72 bytes
        return False


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------


class TokenError(Exception):
    """El token es inválido, está mal firmado o expiró."""


def _secret_key() -> str:
    """Devuelve la clave para firmar tokens; falla si no está configurada."""
    if not config.SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY no está configurada. Defínala en el archivo .env "
            "(ver .env.example)."
        )
    return config.SECRET_KEY


def create_access_token(user_id: int) -> tuple[str, datetime]:
    """
    Crea un JWT firmado para el usuario.

    Claims del token:
    - sub: id del usuario (como texto, según el estándar JWT).
    - iat: fecha de emisión.
    - exp: fecha de expiración (la verifica automáticamente jwt.decode).
    - jti: identificador único, para que dos tokens nunca sean iguales.

    Devuelve el token y su fecha de expiración.
    """
    now = utcnow()
    expires_at = now + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": expires_at,
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(payload, _secret_key(), algorithm=config.ALGORITHM)
    return token, expires_at


def decode_access_token(token: str) -> int:
    """
    Valida un JWT y devuelve el id del usuario.

    Lanza TokenError si la firma no coincide, el token expiró o le faltan datos.
    Se fija el algoritmo permitido para evitar ataques que cambian el "alg"
    del encabezado (por ejemplo a "none").
    """
    try:
        payload = jwt.decode(token, _secret_key(), algorithms=[config.ALGORITHM])
        return int(payload["sub"])
    except (JWTError, KeyError, ValueError, TypeError) as exc:
        raise TokenError("Token inválido o expirado") from exc


# ---------------------------------------------------------------------------
# Sesiones (tabla login_sessions)
# ---------------------------------------------------------------------------


def create_session(db: Session, user: User) -> tuple[str, int]:
    """
    Inicia una sesión: crea el JWT y lo registra en login_sessions.

    Aprovecha para borrar las sesiones expiradas del usuario y que la tabla
    no crezca indefinidamente. Devuelve el token y los segundos de validez.
    """
    db.execute(
        delete(LoginSession).where(
            LoginSession.user_id == user.id, LoginSession.expires_at <= utcnow()
        )
    )
    token, expires_at = create_access_token(user.id)
    db.add(LoginSession(user_id=user.id, token=token, expires_at=expires_at))
    db.commit()
    return token, config.ACCESS_TOKEN_EXPIRE_MINUTES * 60


def get_active_session(db: Session, token: str) -> LoginSession | None:
    """Busca la sesión del token; devuelve None si no existe (revocada) o expiró."""
    session = db.scalar(select(LoginSession).where(LoginSession.token == token))
    if session is None or not session.is_active():
        return None
    return session


def revoke_session(db: Session, token: str) -> None:
    """Cierra la sesión borrando su registro: el token queda revocado."""
    db.execute(delete(LoginSession).where(LoginSession.token == token))
    db.commit()
