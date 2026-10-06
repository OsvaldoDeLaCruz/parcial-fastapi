"""
Endpoints del perfil de usuario (/users). Todos requieren token JWT.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.database import get_db
from app.middleware import get_current_token, get_current_user
from app.models import LoginSession, User
from app.schemas import UserResponse, UserUpdate
from app.security import hash_password, verify_password

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["Usuarios"])


@router.get(
    "/profile",
    response_model=UserResponse,
    summary="Ver perfil del usuario",
    responses={401: {"description": "No autenticado"}},
)
def get_profile(user: User = Depends(get_current_user)):
    """Devuelve los datos del usuario autenticado (sin la contraseña)."""
    return user


@router.put(
    "/profile",
    response_model=UserResponse,
    summary="Actualizar perfil",
    responses={
        400: {"description": "La contraseña actual es incorrecta"},
        401: {"description": "No autenticado"},
    },
)
def update_profile(
    data: UserUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    token: str = Depends(get_current_token),
):
    """
    Actualiza el nombre y/o la contraseña del usuario autenticado.

    Al cambiar la contraseña se cierran todas las demás sesiones del usuario
    (por si alguien más tenía acceso); la sesión actual se mantiene.
    """
    if data.full_name is not None:
        user.full_name = data.full_name

    if data.new_password is not None:
        if not verify_password(data.current_password, user.password_hash):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="La contraseña actual es incorrecta")
        user.password_hash = hash_password(data.new_password)
        db.execute(
            delete(LoginSession).where(LoginSession.user_id == user.id, LoginSession.token != token)
        )
        logger.info("Contraseña actualizada: user_id=%s", user.id)

    db.commit()
    db.refresh(user)
    return user
