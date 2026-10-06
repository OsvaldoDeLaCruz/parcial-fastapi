"""Tests unitarios de app/services/email_service.py (con un servidor SMTP simulado)."""

import smtplib
from unittest.mock import patch

import pytest

from app import config
from app.services.email_service import EmailSendError, build_otp_message, send_otp_email

pytestmark = pytest.mark.unit


@pytest.fixture
def smtp_config(monkeypatch):
    """Configura credenciales SMTP falsas solo durante el test."""
    monkeypatch.setattr(config, "SMTP_USER", "remitente@gmail.com")
    monkeypatch.setattr(config, "SMTP_PASSWORD", "clave-app")
    monkeypatch.setattr(config, "SMTP_FROM", "remitente@gmail.com")
    monkeypatch.setattr(config, "EMAIL_CONSOLE_MODE", False)


def test_build_otp_message_contains_code():
    """El correo va al destinatario correcto y contiene el código."""
    msg = build_otp_message("ana@gmail.com", "Ana", "482913")

    assert msg["To"] == "ana@gmail.com"
    assert "482913" in msg.get_body(("plain",)).get_content()
    assert "482913" in msg.get_body(("html",)).get_content()


def test_send_otp_email_uses_tls_and_login(smtp_config):
    """Se cifra la conexión (STARTTLS), se autentica y se envía el mensaje."""
    with patch("smtplib.SMTP") as smtp_cls:
        server = smtp_cls.return_value.__enter__.return_value
        send_otp_email("ana@gmail.com", "Ana", "482913")

    server.starttls.assert_called_once()
    server.login.assert_called_once_with("remitente@gmail.com", "clave-app")
    server.send_message.assert_called_once()


def test_send_otp_email_raises_on_smtp_error(smtp_config):
    """Si el servidor SMTP falla se lanza EmailSendError (sin exponer detalles)."""
    with patch("smtplib.SMTP", side_effect=smtplib.SMTPAuthenticationError(535, b"bad")):
        with pytest.raises(EmailSendError):
            send_otp_email("ana@gmail.com", "Ana", "482913")


def test_send_otp_email_requires_configuration(monkeypatch):
    """Sin credenciales SMTP no se intenta enviar y se informa el error."""
    monkeypatch.setattr(config, "SMTP_USER", "")
    monkeypatch.setattr(config, "EMAIL_CONSOLE_MODE", False)

    with patch("smtplib.SMTP") as smtp_cls, pytest.raises(EmailSendError):
        send_otp_email("ana@gmail.com", "Ana", "482913")
    smtp_cls.assert_not_called()
