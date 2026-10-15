"""
Manejadores de errores en español.

FastAPI, Pydantic y slowapi generan sus mensajes en inglés
(p. ej. "Field required", "Not Found", "Rate limit exceeded").
Aquí se traducen para que toda la API responda en español.
"""

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException as StarletteHTTPException

# Nombre legible de cada campo de los esquemas
FIELD_NAMES = {
    "email": "El email",
    "password": "La contraseña",
    "full_name": "El nombre",
    "code": "El código",
    "current_password": "La contraseña actual",
    "new_password": "La nueva contraseña",
}

# Mensajes por defecto de Starlette/FastAPI para errores HTTP comunes
HTTP_MESSAGES = {
    "Not Found": "Recurso no encontrado",
    "Method Not Allowed": "Método no permitido",
    "Unauthorized": "No autenticado",
    "Forbidden": "Acceso denegado",
    "Bad Request": "Petición inválida",
}


def translate_validation_error(error: dict) -> str:
    """
    Convierte un error de validación de Pydantic en un mensaje en español.

    `error` es un elemento de exc.errors(), por ejemplo:
    {"type": "string_too_short", "loc": ("body", "password"), "ctx": {"min_length": 8}, ...}
    """
    error_type = error.get("type", "")
    ctx = error.get("ctx") or {}
    loc = error.get("loc") or ()
    field = loc[-1] if loc and isinstance(loc[-1], str) and loc[-1] != "body" else None
    name = FIELD_NAMES.get(field, f"El campo '{field}'" if field else "Los datos")

    if error_type == "missing":
        # "Falta el email" / "Falta la contraseña": así concuerda con cualquier campo
        return f"Falta {name[0].lower()}{name[1:]}"
    if error_type == "string_too_short":
        return f"{name} debe tener al menos {ctx.get('min_length')} caracteres"
    if error_type == "string_too_long":
        return f"{name} no puede tener más de {ctx.get('max_length')} caracteres"
    if error_type == "string_pattern_mismatch" and field == "code":
        return "El código debe tener exactamente 6 dígitos"
    if error_type == "string_pattern_mismatch":
        return f"{name} no tiene el formato correcto"
    if error_type in ("string_type", "int_type", "bool_type"):
        return f"{name} tiene un tipo de dato inválido"
    if error_type == "json_invalid":
        return "El cuerpo de la petición no es un JSON válido"
    if error_type == "value_error" and field == "email":
        return "El email no tiene un formato válido"
    if error_type == "value_error":
        # Errores propios (ValueError de los validadores de schemas.py): ya están
        # en español, solo se quita el prefijo "Value error, " que agrega Pydantic
        return error.get("msg", "").removeprefix("Value error, ")
    return f"{name} tiene un valor no válido"


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Respuesta 422 con los errores de validación traducidos."""
    errors = [
        {
            "campo": loc[-1] if (loc := err.get("loc")) and isinstance(loc[-1], str) else None,
            "msg": translate_validation_error(err),
            "type": err.get("type"),
        }
        for err in exc.errors()
    ]
    return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content={"detail": errors})


async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Respuesta 429 cuando una IP supera el límite de peticiones."""
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Demasiados intentos. Espere un minuto e intente de nuevo."},
        headers={"Retry-After": "60"},
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Traduce los mensajes HTTP por defecto (404, 405...); los propios ya están en español."""
    detail = HTTP_MESSAGES.get(exc.detail, exc.detail) if isinstance(exc.detail, str) else exc.detail
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": detail},
        headers=getattr(exc, "headers", None),
    )


def register_error_handlers(app: FastAPI) -> None:
    """Registra todos los manejadores de errores en la aplicación."""
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(RateLimitExceeded, rate_limit_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
