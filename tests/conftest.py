"""
Configuración compartida de pytest (fixtures).

Las variables de entorno se definen ANTES de importar la app, para que los
tests usen una base de datos temporal y nunca toquen app.db ni envíen correos.
"""

import os
import tempfile

_tmp_dir = tempfile.mkdtemp(prefix="otp_tests_")
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(_tmp_dir, 'test.db')}"
os.environ["SECRET_KEY"] = "clave-secreta-solo-para-tests"
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ["EMAIL_CONSOLE_MODE"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.limiter import limiter  # noqa: E402
from app.main import app  # noqa: E402
from app.models import User  # noqa: E402
from app.security import hash_password  # noqa: E402

TEST_EMAIL = "ana@gmail.com"
TEST_PASSWORD = "Segura123"
TEST_NAME = "Ana Pérez"


@pytest.fixture(autouse=True)
def clean_database():
    """Antes de cada test: borra y vuelve a crear las tablas (cada test empieza vacío)."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def db():
    """Sesión de base de datos para los tests unitarios."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def user(db):
    """Usuario ya registrado en la base de datos."""
    u = User(email=TEST_EMAIL, password_hash=hash_password(TEST_PASSWORD), full_name=TEST_NAME)
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture
def sent_emails(monkeypatch):
    """
    Reemplaza el envío real de correos: guarda cada OTP en una lista.

    Así los tests pueden leer el código "enviado" sin un servidor SMTP.
    """
    sent = []

    def fake_send(to_email, full_name, code):
        """Simula el envío: guarda destinatario y código en vez de mandar el correo."""
        sent.append({"to": to_email, "code": code})

    monkeypatch.setattr("app.routes.auth.send_otp_email", fake_send)
    return sent


@pytest.fixture
def client(sent_emails):
    """Cliente HTTP de pruebas para llamar a los endpoints sin levantar el servidor."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def rate_limit_enabled():
    """Activa el rate limiting solo durante el test que lo pida."""
    limiter.reset()
    limiter.enabled = True
    yield
    limiter.enabled = False
    limiter.reset()


def login_and_get_token(client, sent_emails, email=TEST_EMAIL, password=TEST_PASSWORD) -> str:
    """Hace login + verify-otp y devuelve el token JWT."""
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    code = sent_emails[-1]["code"]
    r = client.post("/auth/verify-otp", json={"email": email, "code": code})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture
def auth_headers(client, sent_emails, user):
    """Encabezado Authorization de un usuario con sesión iniciada."""
    token = login_and_get_token(client, sent_emails)
    return {"Authorization": f"Bearer {token}"}
