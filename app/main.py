"""
Aplicación principal: crea la app FastAPI y une todas las piezas.

Ejecutar en desarrollo:
    uvicorn app.main:app --reload

Página web para usuarios:       http://127.0.0.1:8000/
Documentación técnica de la API: http://127.0.0.1:8000/docs
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.responses import FileResponse, JSONResponse

from app import config
from app.database import init_db
from app.errors import register_error_handlers
from app.limiter import limiter
from app.middleware import AuthMiddleware
from app.routes import auth, users

STATIC_DIR = Path(__file__).parent / "static"

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
        "**¿Buscas la página para usuarios?** Está en [/](/).\n\n"
        "Cómo probar la API desde aquí:\n\n"
        "1. `POST /auth/register` — crear cuenta.\n"
        "2. `POST /auth/login` — email y contraseña; se envía un código OTP al correo.\n"
        "3. `POST /auth/verify-otp` — código OTP; se recibe el token JWT.\n"
        "4. Botón **Authorize** — pegar el token para usar las rutas protegidas.\n\n"
        "En cada endpoint: **Try it out** (probar) → completar los datos → **Execute** (ejecutar)."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Rate limiting (slowapi) y mensajes de error en español
app.state.limiter = limiter
register_error_handlers(app)

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


@app.get("/", include_in_schema=False)
def web_page():
    """Página web en español para usar el sistema (registro, login, código OTP y perfil)."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health", tags=["Estado"], summary="Estado del servicio")
def health():
    """Permite comprobar que el servidor está funcionando (Render lo usa en el despliegue)."""
    return {"status": "ok", "docs": "/docs"}
