# Sistema de Autenticación con OTP — FastAPI

API REST de autenticación con **verificación en dos pasos**: después de ingresar email y contraseña, el usuario recibe por correo un código **OTP de 6 dígitos** (válido 15 minutos) y solo al verificarlo obtiene un **token JWT** para acceder a las rutas protegidas.

Parcial — Desarrollo de Software.

- **Repositorio:** <https://github.com/OsvaldoDeLaCruz/parcial-fastapi>
- **API desplegada:** `https://<tu-servicio>.onrender.com` _(completar tras el despliegue)_
- **Documentación interactiva:** `https://<tu-servicio>.onrender.com/docs`

---

## Contenido

1. [Tecnologías](#tecnologías)
2. [Estructura del proyecto](#estructura-del-proyecto)
3. [Instalación local](#instalación-local)
4. [Configuración (.env)](#configuración-env)
5. [Ejecución y uso](#ejecución-y-uso)
6. [Endpoints](#endpoints)
7. [Seguridad](#seguridad)
8. [Tests](#tests)
9. [Despliegue en Render](#despliegue-en-render)
10. [Contribuciones del equipo](#contribuciones-del-equipo)

---

## Tecnologías

| Componente | Herramienta |
|---|---|
| Backend | FastAPI (Python 3.12) |
| ORM | SQLAlchemy 2 |
| Base de datos | SQLite |
| OTP | PyOTP |
| Envío de correos | `smtplib` (librería estándar) |
| Hash de contraseñas | bcrypt |
| Tokens | JWT (python-jose, HS256) |
| Rate limiting | slowapi |
| Servidor | Uvicorn |
| Tests | pytest |

## Estructura del proyecto

```
parcial-fastapi-otp/
├── app/
│   ├── main.py              # Aplicación principal: une middleware, rutas y manejo de errores
│   ├── config.py            # Lee las variables de entorno (.env)
│   ├── database.py          # Conexión a SQLite, sesiones y creación de tablas
│   ├── models.py            # Modelos SQLAlchemy: users, otp_codes, login_sessions
│   ├── schemas.py           # Esquemas Pydantic (validación de entrada/salida)
│   ├── security.py          # bcrypt, creación/validación de JWT y sesiones
│   ├── middleware.py        # Middleware que valida el token en rutas protegidas
│   ├── limiter.py           # Configuración del rate limiting
│   ├── routes/
│   │   ├── auth.py          # /auth/*: register, login, verify-otp, refresh, logout, resend-otp
│   │   └── users.py         # /users/profile (GET, PUT)
│   └── services/
│       ├── otp_service.py   # Generación y verificación de OTP
│       └── email_service.py # Envío de correos por SMTP
├── tests/                   # Tests unitarios y de integración (pytest)
├── .env.example             # Plantilla de variables de entorno
├── .python-version          # Versión de Python para el despliegue
├── render.yaml              # Configuración de despliegue en Render
├── pytest.ini
└── requirements.txt
```

### Base de datos

| Tabla | Campos | Descripción |
|---|---|---|
| `users` | id, email, password_hash, full_name, created_at, updated_at | Usuarios registrados |
| `otp_codes` | id, user_id, code, expires_at, used, created_at | Códigos OTP generados y su expiración |
| `login_sessions` | id, user_id, token, expires_at, created_at | Sesiones y tokens activos |

## Instalación local

**Requisitos:** Python 3.12 y Git.

```powershell
# 1. Clonar el repositorio
git clone https://github.com/OsvaldoDeLaCruz/parcial-fastapi.git
cd parcial-fastapi

# 2. Crear y activar el entorno virtual
py -3.12 -m venv venv
.\venv\Scripts\Activate.ps1        # Windows (PowerShell)
# source venv/bin/activate         # Linux / macOS

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Crear el archivo de configuración
copy .env.example .env             # Windows
# cp .env.example .env             # Linux / macOS
```

Luego editar `.env` (ver siguiente sección).

## Configuración (.env)

| Variable | Descripción | Ejemplo |
|---|---|---|
| `DATABASE_URL` | Ruta de la base de datos | `sqlite:///./app.db` |
| `SECRET_KEY` | Clave para firmar los JWT (**obligatoria**, larga y aleatoria) | ver comando abajo |
| `ALGORITHM` | Algoritmo de firma del JWT | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Duración del token | `30` |
| `OTP_EXPIRE_MINUTES` | Validez del OTP (máximo 15) | `15` |
| `OTP_RESEND_COOLDOWN_SECONDS` | Espera mínima entre reenvíos de OTP | `60` |
| `SMTP_HOST`, `SMTP_PORT` | Servidor de correo | `smtp.gmail.com`, `587` |
| `SMTP_USER`, `SMTP_PASSWORD` | Credenciales SMTP | |
| `SMTP_FROM` | Remitente de los correos | |
| `EMAIL_CONSOLE_MODE` | `true` = muestra el OTP en consola en vez de enviarlo (**solo desarrollo**) | `false` |
| `RATE_LIMIT_ENABLED` | Activa el límite de peticiones | `true` |

Generar una `SECRET_KEY`:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### Configurar el correo

- **Sin correo (pruebas rápidas):** `EMAIL_CONSOLE_MODE=true`. El código OTP aparece en la terminal donde corre el servidor.
- **Gmail (desarrollo local):**
  1. Activar la verificación en 2 pasos en la cuenta de Google.
  2. Crear una contraseña de aplicación en <https://myaccount.google.com/apppasswords>.
  3. `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=587`, `SMTP_USER` y `SMTP_FROM` = tu Gmail, `SMTP_PASSWORD` = la contraseña de aplicación (16 letras).
- **Brevo (producción en Render):** ver [Despliegue en Render](#despliegue-en-render).

## Ejecución y uso

```powershell
uvicorn app.main:app --reload
```

Abrir **<http://127.0.0.1:8000/docs>** (Swagger UI). Las tablas se crean automáticamente al iniciar.

### Flujo de autenticación

```
1. POST /auth/register    {email, password, full_name}        -> 201 usuario creado
2. POST /auth/login       {email, password}                   -> 200 se envía OTP al correo
3. POST /auth/verify-otp  {email, code}                       -> 200 {access_token, ...}
4. Rutas protegidas con el encabezado  Authorization: Bearer <access_token>
```

En `/docs`, después del paso 3, pulsar **Authorize** y pegar el `access_token`.

### Ejemplo con curl

```bash
# Registro
curl -X POST http://127.0.0.1:8000/auth/register -H "Content-Type: application/json" \
     -d '{"email": "ana.perez@gmail.com", "password": "Segura123", "full_name": "Ana Pérez"}'

# Login (envía el OTP al correo)
curl -X POST http://127.0.0.1:8000/auth/login -H "Content-Type: application/json" \
     -d '{"email": "ana.perez@gmail.com", "password": "Segura123"}'

# Verificar OTP (devuelve el token)
curl -X POST http://127.0.0.1:8000/auth/verify-otp -H "Content-Type: application/json" \
     -d '{"email": "ana.perez@gmail.com", "code": "482913"}'

# Ver perfil
curl http://127.0.0.1:8000/users/profile -H "Authorization: Bearer <token>"
```

## Endpoints

| Método | Ruta | Descripción | Auth | Respuestas |
|---|---|---|---|---|
| POST | `/auth/register` | Registrar nuevo usuario | No | 201, 409, 422, 429 |
| POST | `/auth/login` | Login y envío de OTP | No | 200, 401, 422, 429, 503 |
| POST | `/auth/verify-otp` | Verificar OTP y obtener JWT | No | 200, 401, 422, 429 |
| POST | `/auth/refresh` | Refrescar token JWT (revoca el anterior) | Sí | 200, 401 |
| POST | `/auth/logout` | Cerrar sesión y revocar token | Sí | 200, 401 |
| GET | `/users/profile` | Ver perfil del usuario | Sí | 200, 401 |
| PUT | `/users/profile` | Actualizar nombre y/o contraseña | Sí | 200, 400, 401, 422 |
| POST | `/auth/resend-otp` | Reenviar código OTP | No | 200, 400, 429, 503 |
| GET | `/` | Estado del servicio | No | 200 |

**Códigos de estado usados:** 200 OK · 201 creado · 400 petición inválida · 401 no autenticado · 409 conflicto (email ya registrado) · 422 datos con formato inválido · 429 demasiadas peticiones · 500 error interno (mensaje genérico) · 503 no se pudo enviar el correo.

## Seguridad

| Medida | Implementación |
|---|---|
| Contraseñas hasheadas | bcrypt con sal aleatoria (`app/security.py`). Nunca se guardan ni se devuelven en texto plano. |
| Política de contraseñas | 8–72 caracteres, al menos una letra y un número (`app/schemas.py`). |
| OTP | 6 dígitos generados con PyOTP; válido máx. 15 min; de un solo uso; generar uno nuevo invalida el anterior; comparación en tiempo constante (`hmac.compare_digest`). |
| JWT con expiración | Claims `sub`, `iat`, `exp`, `jti`; firma HS256; algoritmo fijo al decodificar (bloquea `alg: none`). |
| Revocación de tokens | Cada token se registra en `login_sessions`. El middleware exige que la sesión exista: `logout` y `refresh` la borran y el token deja de funcionar al instante. |
| Middleware | `AuthMiddleware` valida encabezado Bearer, firma, expiración y sesión activa en `/users/*`, `/auth/refresh` y `/auth/logout`. |
| Rate limiting | Por IP: 5/min en register, login y verify-otp; 3/min en resend-otp. Además, 60 s de espera entre reenvíos de OTP. |
| Sin fugas de información | Mismo mensaje si el email no existe o la contraseña es incorrecta; errores 500 genéricos; los logs no incluyen contraseñas, OTP ni tokens. |
| Reenvío de OTP protegido | `resend-otp` solo funciona tras un login con contraseña correcta (no permite saltarse la contraseña). |
| Cambio de contraseña | Exige la contraseña actual y cierra las demás sesiones del usuario. |
| Secretos fuera del código | Todo se lee de variables de entorno; `.env` está en `.gitignore`. |

## Tests

```powershell
pytest                    # todos (62 casos)
pytest -m unit            # solo unitarios
pytest -m integration     # solo integración
```

Los tests usan una base de datos temporal y un envío de correo simulado: no tocan `app.db` ni envían correos reales.

| Archivo | Tipo | Qué prueba |
|---|---|---|
| `test_unit_security.py` | Unitario | bcrypt, JWT (válido, expirado, otra clave, `alg: none`), rutas protegidas |
| `test_unit_otp_service.py` | Unitario | 6 dígitos, expiración, un solo uso, invalidación, espera de reenvío |
| `test_unit_schemas.py` | Unitario | Validación de email, contraseña, OTP y actualización de perfil |
| `test_unit_email_service.py` | Unitario | Envío SMTP simulado: STARTTLS/SSL, login, errores |
| `test_integration_auth.py` | Integración | Flujo completo, errores 401/409/422/503, refresh, logout, resend, perfil, rate limiting |

## Despliegue en Render

> **Importante:** el plan gratuito de Render bloquea los puertos SMTP 465 y 587, así que Gmail no funciona desde el servidor. Se usa **Brevo** (gratis, 300 correos/día) por el puerto **2525**, que sí está permitido. El envío sigue haciéndose con `smtplib`.

### 1. Configurar Brevo

1. Crear una cuenta gratuita en <https://www.brevo.com>.
2. **Senders, Domains & Dedicated IPs → Senders**: agregar y verificar el correo remitente (por ejemplo, tu Gmail).
3. **SMTP & API → SMTP**: generar una **SMTP key**. Anotar el **login SMTP** (algo como `xxxx@smtp-brevo.com`) y la clave.

### 2. Subir el código a GitHub

```powershell
git remote add origin https://github.com/OsvaldoDeLaCruz/parcial-fastapi.git
git push -u origin master
```

### 3. Crear el servicio en Render

1. En <https://render.com>: **New → Blueprint** y seleccionar el repositorio. Render lee `render.yaml`.
2. Completar las variables que pide:
   - `SMTP_USER` = login SMTP de Brevo
   - `SMTP_PASSWORD` = SMTP key de Brevo
   - `SMTP_FROM` = remitente verificado en Brevo
3. `SECRET_KEY` se genera automáticamente.
4. Esperar el build. En **Logs** debe aparecer `Aplicación iniciada` y `Uvicorn running on http://0.0.0.0:...` (captura para la evidencia de despliegue).

Configuración aplicada (`render.yaml`):

- **Build:** `pip install -r requirements.txt`
- **Start:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT --proxy-headers`
  (`--proxy-headers` junto con la variable `FORWARDED_ALLOW_IPS=*` hace que el rate limiting vea la IP real del cliente detrás del proxy de Render).
- **Python:** 3.12.10 (archivo `.python-version`).

### Limitaciones del plan gratuito

- El servicio se suspende tras ~15 minutos sin tráfico; la primera petición después tarda unos segundos.
- El disco no es persistente: **la base SQLite se reinicia** en cada despliegue o reinicio (las tablas se vuelven a crear solas). Para datos permanentes habría que usar un disco persistente (plan de pago) o una base de datos externa.

## Contribuciones del equipo

| Integrante | Responsabilidad | Archivos |
|---|---|---|
| Osvaldo De la cruz | | |
| | | |
| | | |

Las contribuciones individuales pueden verificarse con `git log --author="<nombre>"`.
