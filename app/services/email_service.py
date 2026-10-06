"""
Servicio de correo: envía los códigos OTP usando smtplib (librería estándar).

Funciona con cualquier servidor SMTP:
- Gmail (desarrollo local): smtp.gmail.com:587 con una "contraseña de aplicación".
- Brevo (producción en Render): smtp-relay.brevo.com:2525, porque Render
  bloquea los puertos SMTP 465 y 587 en el plan gratuito.
"""

import logging
import smtplib
from email.message import EmailMessage

from app import config

logger = logging.getLogger(__name__)


class EmailSendError(Exception):
    """El correo no se pudo enviar (servidor caído, credenciales mal configuradas, etc.)."""


def build_otp_message(to_email: str, full_name: str, code: str) -> EmailMessage:
    """
    Arma el correo con el código OTP.

    Incluye una versión en texto plano y otra en HTML: el cliente de correo
    muestra la que pueda.
    """
    minutes = config.OTP_EXPIRE_MINUTES

    msg = EmailMessage()
    msg["Subject"] = "Tu código de verificación"
    msg["From"] = config.SMTP_FROM
    msg["To"] = to_email

    msg.set_content(
        f"Hola {full_name},\n\n"
        f"Tu código de verificación es: {code}\n\n"
        f"Es válido por {minutes} minutos y solo se puede usar una vez.\n"
        "Si no intentaste iniciar sesión, ignora este correo.\n"
    )
    msg.add_alternative(
        f"""\
<html>
  <body style="font-family: Arial, sans-serif; color: #222;">
    <p>Hola {full_name},</p>
    <p>Tu código de verificación es:</p>
    <p style="font-size: 28px; font-weight: bold; letter-spacing: 6px;">{code}</p>
    <p>Es válido por <b>{minutes} minutos</b> y solo se puede usar una vez.</p>
    <p style="color: #777; font-size: 12px;">
      Si no intentaste iniciar sesión, ignora este correo.
    </p>
  </body>
</html>
""",
        subtype="html",
    )
    return msg


def send_otp_email(to_email: str, full_name: str, code: str) -> None:
    """
    Envía el código OTP al correo del usuario.

    Lanza EmailSendError si no se pudo enviar. Los mensajes de error en los
    logs no incluyen el código ni las credenciales SMTP.
    """
    # Modo desarrollo: muestra el código en consola en lugar de enviarlo
    if config.EMAIL_CONSOLE_MODE:
        logger.warning("[EMAIL_CONSOLE_MODE] OTP para %s: %s", to_email, code)
        return

    if not config.SMTP_USER or not config.SMTP_PASSWORD:
        logger.error("SMTP no configurado: faltan SMTP_USER o SMTP_PASSWORD")
        raise EmailSendError("El servicio de correo no está configurado")

    msg = build_otp_message(to_email, full_name, code)

    try:
        # Puerto 465: conexión cifrada (SSL) desde el inicio.
        # Puertos 587 / 2525: conexión normal que luego se cifra con STARTTLS.
        use_ssl = config.SMTP_PORT == 465
        smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
        with smtp_class(config.SMTP_HOST, config.SMTP_PORT, timeout=10) as server:
            if not use_ssl:
                server.starttls()  # cifra la conexión antes de enviar usuario y contraseña
            server.login(config.SMTP_USER, config.SMTP_PASSWORD)
            server.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        # Solo se registra el tipo de error, no el detalle (podría contener datos sensibles)
        logger.error("Error enviando correo OTP: %s", type(exc).__name__)
        raise EmailSendError("No se pudo enviar el correo de verificación") from exc

    logger.info("Correo OTP enviado a %s", to_email)
