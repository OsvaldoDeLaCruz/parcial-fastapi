"""
Endpoints de autenticación (/auth).

Flujo de inicio de sesión en dos pasos (2FA):
1. POST /auth/login       -> email + contraseña correctos: se envía un OTP al correo.
2. POST /auth/verify-otp  -> email + OTP correctos: se entrega el token JWT.

Con el token se accede a las rutas protegidas, se refresca (/auth/refresh)
o se cierra la sesión (/auth/logout).
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.limiter import LOGIN_LIMIT, REGISTER_LIMIT, RESEND_OTP_LIMIT, VERIFY_OTP_LIMIT, limiter
from app.middleware import get_current_token, get_current_user
from app.models import User
from app.schemas import (
    MessageResponse,
    OTPResend,
    OTPVerify,
    TokenResponse,
    UserLogin,
    UserRegister,
    UserResponse,
)
from app.security import create_session, hash_password, revoke_session, verify_password
from app.services import otp_service
from app.services.email_service import EmailSendError, send_otp_email

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Autenticación"])

# Mensajes genéricos: no revelan si falló el email o la contraseña
INVALID_CREDENTIALS = "Email o contraseña incorrectos"
INVALID_OTP = "Código inválido o expirado"


def get_user_by_email(db: Session, email: str) -> User | None:
    """Busca un usuario por su email (ya normalizado a minúsculas por el esquema)."""
    return db.scalar(select(User).where(User.email == email))


def send_new_otp(db: Session, user: User) -> None:
    """
    Genera un OTP nuevo y lo envía por correo.

    Si el correo falla, invalida el código recién creado (nadie lo recibió)
    y responde 503 Service Unavailable.
    """
    code = otp_service.create_otp(db, user)
    try:
        send_otp_email(user.email, user.full_name, code)
    except EmailSendError:
        otp_service.invalidate_user_otps(db, user)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No se pudo enviar el código de verificación. Intente más tarde.",
        )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar nuevo usuario",
    responses={409: {"description": "El email ya está registrado"}},
)
@limiter.limit(REGISTER_LIMIT)
def register(request: Request, data: UserRegister, db: Session = Depends(get_db)):
    """Crea un usuario nuevo. La contraseña se guarda como hash bcrypt."""
    if get_user_by_email(db, data.email):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="El email ya está registrado")

    user = User(
        email=data.email,
        password_hash=hash_password(data.password),
        full_name=data.full_name,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        # Dos registros simultáneos con el mismo email: la BD rechaza el segundo
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="El email ya está registrado")
    db.refresh(user)
    logger.info("Usuario registrado: id=%s", user.id)
    return user


@router.post(
    "/login",
    response_model=MessageResponse,
    summary="Login y envío de OTP",
    responses={401: {"description": "Credenciales incorrectas"}, 503: {"description": "Error enviando el correo"}},
)
@limiter.limit(LOGIN_LIMIT)
def login(request: Request, data: UserLogin, db: Session = Depends(get_db)):
    """
    Primer paso del login: valida email y contraseña y envía un OTP al correo.

    Todavía no entrega el token; para obtenerlo se debe llamar a /auth/verify-otp.
    """
    user = get_user_by_email(db, data.email)
    # Se responde lo mismo si el email no existe o si la contraseña está mal,
    # para no revelar qué emails están registrados
    if user is None or not verify_password(data.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=INVALID_CREDENTIALS)

    send_new_otp(db, user)
    return MessageResponse(message="Se envió un código de verificación a su correo")


@router.post(
    "/verify-otp",
    response_model=TokenResponse,
    summary="Verificar OTP y obtener JWT",
    responses={401: {"description": "Código inválido o expirado"}},
)
@limiter.limit(VERIFY_OTP_LIMIT)
def verify_otp(request: Request, data: OTPVerify, db: Session = Depends(get_db)):
    """Segundo paso del login: si el OTP es correcto, crea la sesión y devuelve el JWT."""
    user = get_user_by_email(db, data.email)
    if user is None or not otp_service.verify_otp(db, user, data.code):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=INVALID_OTP)

    token, expires_in = create_session(db, user)
    logger.info("Inicio de sesión exitoso: user_id=%s", user.id)
    return TokenResponse(access_token=token, expires_in=expires_in)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refrescar token JWT",
    responses={401: {"description": "Token inválido, expirado o revocado"}},
)
def refresh(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    token: str = Depends(get_current_token),
):
    """Entrega un token nuevo con expiración renovada y revoca el token anterior."""
    new_token, expires_in = create_session(db, user)
    revoke_session(db, token)
    return TokenResponse(access_token=new_token, expires_in=expires_in)


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Cerrar sesión",
    responses={401: {"description": "Token inválido, expirado o revocado"}},
)
def logout(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    token: str = Depends(get_current_token),
):
    """Cierra la sesión: el token queda revocado aunque todavía no haya expirado."""
    revoke_session(db, token)
    logger.info("Sesión cerrada: user_id=%s", user.id)
    return MessageResponse(message="Sesión cerrada correctamente")


@router.post(
    "/resend-otp",
    response_model=MessageResponse,
    summary="Reenviar código OTP",
    responses={
        400: {"description": "No hay un inicio de sesión pendiente"},
        429: {"description": "Debe esperar antes de pedir otro código"},
    },
)
@limiter.limit(RESEND_OTP_LIMIT)
def resend_otp(request: Request, data: OTPResend, db: Session = Depends(get_db)):
    """
    Envía un código OTP nuevo (el anterior deja de ser válido).

    Solo funciona si el usuario hizo login con contraseña en los últimos
    minutos; así nadie puede saltarse la contraseña pidiendo códigos.
    """
    user = get_user_by_email(db, data.email)
    if user is None or not otp_service.has_pending_login(db, user):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="No hay un inicio de sesión pendiente. Inicie sesión con su contraseña.",
        )

    wait = otp_service.seconds_until_resend(db, user)
    if wait > 0:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Debe esperar {wait} segundos antes de pedir otro código",
            headers={"Retry-After": str(wait)},
        )

    send_new_otp(db, user)
    return MessageResponse(message="Se envió un nuevo código de verificación a su correo")
