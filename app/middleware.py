"""
Middleware de autenticación.

Un middleware se ejecuta ANTES de cada endpoint. Este revisa las peticiones
a rutas protegidas y solo las deja pasar si traen un token válido:

    Authorization: Bearer <token>

Validaciones (en orden):
1. Que exista el encabezado Authorization con formato "Bearer <token>".
2. Que el JWT tenga firma válida y no haya expirado.
3. Que la sesión del token siga activa en login_sessions (no se hizo logout).

Si todo es correcto guarda user_id y token en `request.state` para que los
endpoints los usen (ver get_current_user). Si no, responde 401.
"""

import logging

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from app import database
from app.database import get_db
from app.models import User
from app.security import TokenError, decode_access_token, get_active_session

logger = logging.getLogger(__name__)

# Rutas que requieren token (columna "Auth: Sí" del enunciado)
PROTECTED_PATHS = ("/users/", "/auth/refresh", "/auth/logout")


def is_protected(path: str) -> bool:
    """Indica si la ruta requiere autenticación."""
    path = path.rstrip("/") + "/"
    return any(path.startswith(p.rstrip("/") + "/") for p in PROTECTED_PATHS)


def unauthorized(detail: str) -> JSONResponse:
    """Respuesta 401 estándar, con el encabezado que indica usar un token Bearer."""
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": detail},
        headers={"WWW-Authenticate": "Bearer"},
    )


class AuthMiddleware(BaseHTTPMiddleware):
    """Valida el token JWT y la sesión en todas las rutas protegidas."""

    async def dispatch(self, request: Request, call_next):
        # Las peticiones OPTIONS (CORS) y las rutas públicas pasan sin validar
        if request.method == "OPTIONS" or not is_protected(request.url.path):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        scheme, _, token = auth_header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return unauthorized("No autenticado: falta el token Bearer")
        token = token.strip()

        try:
            user_id = decode_access_token(token)
        except TokenError:
            return unauthorized("Token inválido o expirado")

        # Se busca la sesión en la BD: si se hizo logout, ya no existe
        db = database.SessionLocal()
        try:
            session = get_active_session(db, token)
        finally:
            db.close()

        if session is None or session.user_id != user_id:
            logger.info("Intento de acceso con sesión revocada o expirada (user_id=%s)", user_id)
            return unauthorized("La sesión fue cerrada o expiró")

        request.state.user_id = user_id
        request.state.token = token
        return await call_next(request)


# Solo para la documentación (/docs): agrega el botón "Authorize".
# La validación real la hace AuthMiddleware.
bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    _credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> User:
    """
    Dependencia para los endpoints protegidos: devuelve el usuario autenticado.

    Uso: `user: User = Depends(get_current_user)`.
    Lee el user_id que dejó AuthMiddleware en request.state.
    """
    user_id = getattr(request.state, "user_id", None)
    user = db.get(User, user_id) if user_id is not None else None
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No autenticado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_current_token(request: Request) -> str:
    """Devuelve el token de la petición actual (lo usan logout y refresh)."""
    token = getattr(request.state, "token", None)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No autenticado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token
