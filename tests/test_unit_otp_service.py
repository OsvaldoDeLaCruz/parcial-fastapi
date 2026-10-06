"""Tests unitarios de app/services/otp_service.py."""

from datetime import timedelta

import pytest

from app.models import OTPCode, utcnow
from app.services import otp_service

pytestmark = pytest.mark.unit


def test_generate_otp_code_has_six_digits():
    """Todos los códigos generados tienen exactamente 6 dígitos."""
    codes = [otp_service.generate_otp_code() for _ in range(200)]

    assert all(len(c) == 6 and c.isdigit() for c in codes)
    assert len(set(codes)) > 190  # son aleatorios, casi nunca se repiten


def test_create_otp_expires_in_at_most_15_minutes(db, user):
    """El OTP se guarda con una validez máxima de 15 minutos."""
    otp_service.create_otp(db, user)
    otp = db.query(OTPCode).one()

    validity = otp.expires_at - otp.created_at
    assert timedelta(minutes=14) < validity <= timedelta(minutes=15)
    assert otp.used is False


def test_verify_otp_correct_code_only_once(db, user):
    """El código correcto se acepta una sola vez; un código incorrecto nunca."""
    code = otp_service.create_otp(db, user)
    wrong = "000000" if code != "000000" else "111111"

    assert otp_service.verify_otp(db, user, wrong) is False
    assert otp_service.verify_otp(db, user, code) is True
    assert otp_service.verify_otp(db, user, code) is False  # ya usado


def test_verify_otp_rejects_expired_code(db, user):
    """Un código vencido no se acepta aunque sea correcto."""
    code = otp_service.create_otp(db, user)
    db.query(OTPCode).update({"expires_at": utcnow() - timedelta(seconds=1)})
    db.commit()

    assert otp_service.verify_otp(db, user, code) is False


def test_new_otp_invalidates_previous(db, user):
    """Al generar un código nuevo, el anterior deja de ser válido."""
    first = otp_service.create_otp(db, user)
    second = otp_service.create_otp(db, user)

    pending = db.query(OTPCode).filter_by(used=False).all()
    assert len(pending) == 1
    assert pending[0].code == second
    if first != second:
        assert otp_service.verify_otp(db, user, first) is False


def test_resend_cooldown_and_pending_login(db, user):
    """Hay que esperar entre reenvíos, y solo hay login pendiente si hubo un OTP reciente."""
    assert otp_service.has_pending_login(db, user) is False
    assert otp_service.seconds_until_resend(db, user) == 0

    otp_service.create_otp(db, user)
    assert otp_service.has_pending_login(db, user) is True
    assert otp_service.seconds_until_resend(db, user) > 0

    # Simula que el OTP se creó hace 20 minutos
    db.query(OTPCode).update({"created_at": utcnow() - timedelta(minutes=20)})
    db.commit()
    assert otp_service.seconds_until_resend(db, user) == 0
    assert otp_service.has_pending_login(db, user) is False
