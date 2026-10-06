"""
Configuración central de la aplicación.

Todas las variables se leen del archivo .env (o de las variables de entorno
del servidor en producción). Así ninguna contraseña ni clave queda escrita
en el código fuente.
"""

import os

from dotenv import load_dotenv

load_dotenv()


def _get_bool(name: str, default: bool = False) -> bool:
    """Lee una variable de entorno como booleano ('true', '1', 'yes' -> True)."""
    return os.getenv(name, str(default)).strip().lower() in ("true", "1", "yes")


# Base de datos
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

# JWT
SECRET_KEY = os.getenv("SECRET_KEY", "")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# OTP: el enunciado exige una validez máxima de 15 minutos, por eso se limita con min()
OTP_EXPIRE_MINUTES = min(int(os.getenv("OTP_EXPIRE_MINUTES", "15")), 15)
# Tiempo mínimo entre dos reenvíos de OTP para el mismo usuario
OTP_RESEND_COOLDOWN_SECONDS = int(os.getenv("OTP_RESEND_COOLDOWN_SECONDS", "60"))

# SMTP
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)
# Solo para desarrollo local: en vez de enviar el correo, muestra el OTP en la consola.
# NUNCA activar en producción.
EMAIL_CONSOLE_MODE = _get_bool("EMAIL_CONSOLE_MODE", False)
