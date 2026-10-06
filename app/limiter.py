"""
Rate limiting: limita cuántas peticiones puede hacer una misma IP por minuto.

Protege los endpoints críticos (login, verificación de OTP, registro, reenvío)
contra ataques de fuerza bruta: por ejemplo, sin límite un atacante podría
probar los 1.000.000 de códigos OTP posibles.

Uso en un endpoint (el endpoint debe recibir `request: Request`):

    @router.post("/login")
    @limiter.limit(LOGIN_LIMIT)
    def login(request: Request, ...):
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import RATE_LIMIT_ENABLED

limiter = Limiter(key_func=get_remote_address, enabled=RATE_LIMIT_ENABLED)

# Límites por IP para cada endpoint crítico
REGISTER_LIMIT = "5/minute"
LOGIN_LIMIT = "5/minute"
VERIFY_OTP_LIMIT = "5/minute"
RESEND_OTP_LIMIT = "3/minute"
