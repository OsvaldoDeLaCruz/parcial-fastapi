"""
Tests de integración: llaman a los endpoints por HTTP (TestClient) y
recorren todas las capas: rutas -> middleware -> servicios -> base de datos.
"""

from datetime import timedelta

import pytest

from app.database import SessionLocal
from app.models import OTPCode, utcnow
from app.services.email_service import EmailSendError
from tests.conftest import TEST_EMAIL, TEST_NAME, TEST_PASSWORD, login_and_get_token

pytestmark = pytest.mark.integration


def test_full_authentication_flow(client, sent_emails):
    """Registro -> login -> OTP por correo -> JWT -> perfil -> logout -> token revocado."""
    r = client.post(
        "/auth/register",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD, "full_name": TEST_NAME},
    )
    assert r.status_code == 201
    assert "password_hash" not in r.json()

    r = client.post("/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD})
    assert r.status_code == 200
    assert len(sent_emails) == 1
    assert sent_emails[0]["to"] == TEST_EMAIL
    assert sent_emails[0]["code"] not in r.text  # el OTP nunca viaja en la respuesta

    r = client.post("/auth/verify-otp", json={"email": TEST_EMAIL, "code": sent_emails[0]["code"]})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0
    headers = {"Authorization": f"Bearer {body['access_token']}"}

    r = client.get("/users/profile", headers=headers)
    assert r.status_code == 200
    assert r.json()["email"] == TEST_EMAIL

    r = client.post("/auth/logout", headers=headers)
    assert r.status_code == 200

    r = client.get("/users/profile", headers=headers)
    assert r.status_code == 401


def test_register_duplicate_and_invalid_data(client, user):
    """Email repetido -> 409; datos inválidos -> 422."""
    r = client.post(
        "/auth/register",
        json={"email": TEST_EMAIL.upper(), "password": TEST_PASSWORD, "full_name": "Otra"},
    )
    assert r.status_code == 409

    r = client.post("/auth/register", json={"email": "malo", "password": "123", "full_name": "X"})
    assert r.status_code == 422


def test_login_wrong_credentials_same_message(client, sent_emails, user):
    """Email inexistente y contraseña errónea dan el mismo 401 y no envían correo."""
    r1 = client.post("/auth/login", json={"email": TEST_EMAIL, "password": "Incorrecta1"})
    r2 = client.post("/auth/login", json={"email": "nadie@gmail.com", "password": "Incorrecta1"})

    assert r1.status_code == r2.status_code == 401
    assert r1.json() == r2.json()
    assert sent_emails == []


def test_verify_otp_wrong_reused_and_expired(client, sent_emails, user):
    """Un OTP incorrecto, reutilizado o vencido no entrega token."""
    client.post("/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD})
    code = sent_emails[-1]["code"]
    wrong = "000000" if code != "000000" else "111111"

    assert client.post("/auth/verify-otp", json={"email": TEST_EMAIL, "code": wrong}).status_code == 401
    assert client.post("/auth/verify-otp", json={"email": TEST_EMAIL, "code": code}).status_code == 200
    assert client.post("/auth/verify-otp", json={"email": TEST_EMAIL, "code": code}).status_code == 401

    # Nuevo login, pero el código vence antes de usarlo
    client.post("/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD})
    db = SessionLocal()
    db.query(OTPCode).update({"expires_at": utcnow() - timedelta(seconds=1)})
    db.commit()
    db.close()
    r = client.post("/auth/verify-otp", json={"email": TEST_EMAIL, "code": sent_emails[-1]["code"]})
    assert r.status_code == 401


@pytest.mark.parametrize(
    "method, path",
    [("GET", "/users/profile"), ("PUT", "/users/profile"), ("POST", "/auth/refresh"), ("POST", "/auth/logout")],
)
@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer token-falso"}, {"Authorization": "Basic abc"}],
    ids=["sin-token", "token-falso", "esquema-incorrecto"],
)
def test_protected_routes_require_valid_token(client, method, path, headers):
    """Las rutas protegidas responden 401 sin un token válido."""
    r = client.request(method, path, headers=headers, json={"full_name": "X Y"})
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"] == "Bearer"


def test_refresh_issues_new_token_and_revokes_old(client, auth_headers):
    """Refresh entrega un token nuevo que funciona, y el anterior queda revocado."""
    r = client.post("/auth/refresh", headers=auth_headers)
    assert r.status_code == 200
    new_headers = {"Authorization": f"Bearer {r.json()['access_token']}"}

    assert client.get("/users/profile", headers=new_headers).status_code == 200
    assert client.get("/users/profile", headers=auth_headers).status_code == 401


def test_resend_otp_rules(client, sent_emails, user):
    """Resend exige un login previo, respeta la espera y reemplaza el código anterior."""
    r = client.post("/auth/resend-otp", json={"email": TEST_EMAIL})
    assert r.status_code == 400  # sin login previo

    client.post("/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD})
    r = client.post("/auth/resend-otp", json={"email": TEST_EMAIL})
    assert r.status_code == 429  # demasiado pronto
    assert "Retry-After" in r.headers

    # Simula que pasaron 2 minutos desde el último código
    db = SessionLocal()
    db.query(OTPCode).update({"created_at": utcnow() - timedelta(minutes=2)})
    db.commit()
    db.close()

    r = client.post("/auth/resend-otp", json={"email": TEST_EMAIL})
    assert r.status_code == 200
    assert len(sent_emails) == 2

    old_code, new_code = sent_emails[0]["code"], sent_emails[1]["code"]
    if old_code != new_code:
        assert client.post("/auth/verify-otp", json={"email": TEST_EMAIL, "code": old_code}).status_code == 401
    assert client.post("/auth/verify-otp", json={"email": TEST_EMAIL, "code": new_code}).status_code == 200


def test_update_profile_name_and_password(client, sent_emails, auth_headers):
    """Se actualiza el nombre; la contraseña solo cambia con la actual correcta y cierra otras sesiones."""
    r = client.put("/users/profile", headers=auth_headers, json={"full_name": "Ana María"})
    assert r.status_code == 200
    assert r.json()["full_name"] == "Ana María"

    other_session = {"Authorization": f"Bearer {login_and_get_token(client, sent_emails)}"}

    r = client.put(
        "/users/profile",
        headers=auth_headers,
        json={"current_password": "Incorrecta1", "new_password": "NuevaClave9"},
    )
    assert r.status_code == 400

    r = client.put(
        "/users/profile",
        headers=auth_headers,
        json={"current_password": TEST_PASSWORD, "new_password": "NuevaClave9"},
    )
    assert r.status_code == 200

    assert client.get("/users/profile", headers=auth_headers).status_code == 200  # sesión actual sigue
    assert client.get("/users/profile", headers=other_session).status_code == 401  # las otras se cierran
    assert client.post("/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}).status_code == 401
    assert client.post("/auth/login", json={"email": TEST_EMAIL, "password": "NuevaClave9"}).status_code == 200


def test_login_returns_503_when_email_fails(client, monkeypatch, user):
    """Si el correo no se puede enviar responde 503 y el OTP generado queda invalidado."""

    def failing_send(*args):
        """Simula un servidor SMTP caído."""
        raise EmailSendError("SMTP caído")

    monkeypatch.setattr("app.routes.auth.send_otp_email", failing_send)

    r = client.post("/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD})
    assert r.status_code == 503

    db = SessionLocal()
    assert db.query(OTPCode).filter_by(used=False).count() == 0
    db.close()


def test_rate_limit_blocks_brute_force(client, user, rate_limit_enabled):
    """Tras 5 intentos por minuto en verify-otp, la API responde 429."""
    statuses = [
        client.post("/auth/verify-otp", json={"email": TEST_EMAIL, "code": "000000"}).status_code
        for _ in range(7)
    ]
    assert statuses[:5] == [401] * 5
    assert statuses[5:] == [429, 429]


def test_web_page_health_and_docs_are_public(client):
    """La página web, el estado del servicio y la documentación no requieren token."""
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert '<html lang="es">' in r.text

    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_error_messages_are_in_spanish(client):
    """Los errores de validación, 404, 405 y 429 se responden en español."""
    r = client.post("/auth/register", json={"email": "malo", "password": "ab"})
    assert r.status_code == 422
    messages = {e["campo"]: e["msg"] for e in r.json()["detail"]}
    assert messages == {
        "email": "El email no tiene un formato válido",
        "password": "La contraseña debe tener al menos 8 caracteres",
        "full_name": "Falta el nombre",
    }

    r = client.post("/auth/login", json={"email": TEST_EMAIL})
    assert r.json()["detail"][0]["msg"] == "Falta la contraseña"

    r = client.post("/auth/verify-otp", json={"email": TEST_EMAIL, "code": "12a"})
    assert r.json()["detail"][0]["msg"] == "El código debe tener exactamente 6 dígitos"

    r = client.post("/auth/register", json={"email": "a@gmail.com", "password": "SoloLetras", "full_name": "Ana"})
    assert r.json()["detail"][0]["msg"] == "La contraseña debe contener al menos una letra y un número"

    assert client.get("/no-existe").json() == {"detail": "Recurso no encontrado"}
    assert client.delete("/auth/login").json() == {"detail": "Método no permitido"}


def test_rate_limit_message_in_spanish(client, user, rate_limit_enabled):
    """El mensaje de límite de peticiones también está en español."""
    for _ in range(5):
        client.post("/auth/login", json={"email": TEST_EMAIL, "password": "Incorrecta1"})
    r = client.post("/auth/login", json={"email": TEST_EMAIL, "password": "Incorrecta1"})
    assert r.status_code == 429
    assert r.json() == {"detail": "Demasiados intentos. Espere un minuto e intente de nuevo."}
    assert r.headers["Retry-After"] == "60"
