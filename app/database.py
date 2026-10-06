"""
Configuración de la base de datos (SQLite + SQLAlchemy).

Aquí se crean tres piezas que usa el resto de la aplicación:
- engine: la conexión a la base de datos.
- SessionLocal: fábrica de sesiones (cada petición HTTP usa su propia sesión).
- Base: clase de la que heredan todos los modelos de models.py.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import DATABASE_URL

# SQLite por defecto solo permite usar una conexión en el hilo que la creó.
# FastAPI atiende peticiones en varios hilos, por eso se desactiva esa restricción.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    """Clase base de la que heredan todos los modelos SQLAlchemy."""


def get_db():
    """
    Dependencia de FastAPI que entrega una sesión de base de datos.

    Se usa en los endpoints con `db: Session = Depends(get_db)`.
    El `finally` garantiza que la sesión se cierre aunque ocurra un error.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Crea en la base de datos todas las tablas definidas en models.py (si no existen)."""
    from app import models  # noqa: F401  (importar registra los modelos en Base)

    Base.metadata.create_all(bind=engine)
