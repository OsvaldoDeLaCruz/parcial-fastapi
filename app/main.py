"""
Aplicación principal: crea la app FastAPI y une todas las piezas.

Ejecutar en desarrollo:
    uvicorn app.main:app --reload

Documentación interactiva: http://127.0.0.1:8000/docs
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app import config
from app.database import init_db
from app.limiter import limiter
from app.middleware import AuthMiddleware
from app.routes import auth, users

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Se ejecuta al arrancar el servidor: valida la configuración y crea las tablas."""
    if not config.SECRET_KEY:
        raise RuntimeError("SECRET_KEY no está configurada. Defínala en el archivo .env")
    if config.EMAIL_CONSOLE_MODE:
        logger.warning("EMAIL_CONSOLE_MODE activo: los OTP se muestran en consola (solo desarrollo)")
    init_db()
    logger.info("Aplicación iniciada")
    yield


app = FastAPI(
    title="Sistema de Autenticación con OTP",
    description=(
        "API de autenticación con verificación en dos pasos.\n\n"
        "1. `POST /auth/register` — crear cuenta.\n"
        "2. `POST /auth/login` — email y contraseña; se envía un código OTP al correo.\n"
        "3. `POST /auth/verify-otp` — código OTP; se recibe el token JWT.\n"
        "4. Botón **Authorize** — pegar el token para usar las rutas protegidas."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Rate limiting (slowapi): responde 429 cuando se supera el límite
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware que valida el token en las rutas protegidas
app.add_middleware(AuthMiddleware)

app.include_router(auth.router)
app.include_router(users.router)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """
    Captura cualquier error no previsto y responde 500 con un mensaje genérico.

    El detalle se guarda en los logs del servidor, pero nunca se envía al
    cliente (podría revelar información interna).
    """
    logger.exception("Error no controlado en %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Error interno del servidor"},
    )


@app.get("/", tags=["Estado"], summary="Estado del servicio")
def health():
    """Permite comprobar que el servidor está funcionando (útil en el despliegue)."""
    return {"status": "ok", "docs": "/docs"}
