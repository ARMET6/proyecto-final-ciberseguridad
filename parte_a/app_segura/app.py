"""
Portal Escolar del Campus Las Torres — VERSIÓN CORREGIDA.

Correcciones respecto a app_vulnerable/app.py:
  1. SQL Injection -> consultas parametrizadas (?) y validación de longitud/caracteres.
  2. XSS           -> se quitó |safe (Jinja2 escapa por defecto), cabecera
                      Content-Security-Policy y cookie de sesión HttpOnly/SameSite.
  3. IDOR / BOLA   -> función puede_ver_alumno(), permisos por rol y responsabilidad:
                      alumno = solo su matrícula; docente = solo sus alumnos asignados;
                      servicios escolares = todos los expedientes; admin = gestión de
                      cuentas, sin acceso a expedientes. Lo negado responde 403 y se registra.
Controles adicionales (mejoras de la revisión final):
  - Tokens CSRF (Flask-WTF) en todos los formularios que modifican información.
  - CSP estricta: los estilos viven en static/estilos.css, sin 'unsafe-inline'.
  - La cabecera Server ya no revela Werkzeug ni la versión de Python.
Además (Actividad 5): bitácora de seguridad en JSON (logs/seguridad.log) y
bloqueo temporal tras 5 intentos fallidos de inicio de sesión.

Ejecutar con:
    python parte_a/app_segura/app.py      (puerto 5001)
"""
import json
import logging
import os
import re
import sqlite3
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, g, jsonify, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import check_password_hash
from werkzeug.serving import WSGIRequestHandler

BASE = Path(__file__).resolve().parent.parent
DB_PATH = BASE / "instance" / "campus.db"
LOG_DIR = BASE / "logs"
LOG_DIR.mkdir(exist_ok=True)

app = Flask(__name__, template_folder=str(Path(__file__).resolve().parent / "templates"))
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # JavaScript no puede leer la cookie de sesión
    SESSION_COOKIE_SAMESITE="Lax",
    # En producción con TLS se activaría también: SESSION_COOKIE_SECURE=True
    MAX_CONTENT_LENGTH=16 * 1024,
    WTF_CSRF_TIME_LIMIT=3600,          # el token CSRF vence en 1 hora
)
csrf = CSRFProtect(app)                # exige csrf_token en todo POST

# ------------------------------------------------------------------ bitácora
log = logging.getLogger("seguridad")
log.setLevel(logging.INFO)
_h = logging.FileHandler(LOG_DIR / "seguridad.log", encoding="utf-8")
_h.setFormatter(logging.Formatter("%(message)s"))
log.addHandler(_h)

PATRONES_SOSPECHOSOS = re.compile(
    r"('|--|;|/\*|\bunion\b|\bselect\b|\bor\s+1=1|<\s*script|onerror\s*=|onload\s*=|javascript:)",
    re.IGNORECASE,
)


def evento(tipo, nivel="INFO", **datos):
    """Escribe un evento de seguridad como una línea JSON."""
    u = session.get("usuario")
    registro = {
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "nivel": nivel,
        "evento": tipo,
        "ip": request.remote_addr,
        "usuario": u or "-",
        "metodo": request.method,
        "ruta": request.full_path.rstrip("?"),
        **datos,
    }
    log.info(json.dumps(registro, ensure_ascii=False))


def revisar_entrada(campo, valor):
    """Detecta (no bloquea) patrones típicos de SQLi/XSS para dejar evidencia."""
    if valor and PATRONES_SOSPECHOSOS.search(valor):
        evento("ENTRADA_SOSPECHOSA", "WARNING", campo=campo, valor=valor[:120])


# ------------------------------------------------------------------ base de datos
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(_exc):
    con = g.pop("db", None)
    if con is not None:
        con.close()


@app.context_processor
def version():
    return {"version": "CORREGIDA"}


@app.after_request
def cabeceras_seguridad(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def usuario_actual():
    if "uid" not in session:
        return None
    return db().execute("SELECT * FROM usuarios WHERE id = ?", (session["uid"],)).fetchone()


def requiere_sesion():
    u = usuario_actual()
    if not u:
        evento("NO_AUTENTICADO", "WARNING")
    return u


# ------------------------------------------------------------------ autorización (IDOR)
MATRICULA_RE = re.compile(r"^AL\d{8}$")


def alumnos_asignados(u):
    """Matrículas de los grupos que tiene asignados un docente."""
    filas = db().execute("SELECT matricula FROM asignaciones WHERE docente = ?", (u["usuario"],))
    return {f["matricula"] for f in filas}


def puede_ver_alumno(u, matricula):
    """Regla de autorización sobre el recurso solicitado (mínimo privilegio por rol)."""
    if u["rol"] == "alumno":
        return u["matricula"] == matricula          # solo su propio expediente
    if u["rol"] == "docente":
        return matricula in alumnos_asignados(u)    # solo alumnos de sus grupos
    if u["rol"] == "escolares":
        return True                                 # gestiona expedientes por su función
    return False                                    # admin y cualquier rol nuevo: denegado


def validar_matricula(matricula):
    if not MATRICULA_RE.fullmatch(matricula):
        evento("ENTRADA_INVALIDA", "WARNING", campo="matricula", valor=matricula[:40])
        abort(400)


# ------------------------------------------------------------------ rutas
@app.route("/salud")
def salud():
    return jsonify(estado="ok", version="corregida")


INTENTOS = {}           # usuario -> [marcas de tiempo de intentos fallidos]
MAX_INTENTOS, VENTANA, BLOQUEO = 5, 300, 300     # 5 intentos en 5 min -> 5 min de bloqueo


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        nombre = request.form.get("usuario", "")[:50]
        revisar_entrada("usuario", nombre)
        ahora = time.time()
        recientes = [t for t in INTENTOS.get(nombre, []) if ahora - t < VENTANA]
        if len(recientes) >= MAX_INTENTOS and ahora - recientes[-1] < BLOQUEO:
            evento("CUENTA_BLOQUEADA", "ALERT", cuenta=nombre, intentos=len(recientes))
            return render_template("login.html", error="Cuenta bloqueada temporalmente"), 429
        u = db().execute("SELECT * FROM usuarios WHERE usuario = ?", (nombre,)).fetchone()
        if u and check_password_hash(u["password_hash"], request.form.get("password", "")):
            INTENTOS.pop(nombre, None)
            session.clear()
            session["uid"], session["usuario"] = u["id"], u["usuario"]
            evento("LOGIN_OK", rol=u["rol"])
            return redirect(url_for("inicio"))
        recientes.append(ahora)
        INTENTOS[nombre] = recientes
        evento("LOGIN_FALLIDO", "WARNING", cuenta=nombre, intento=len(recientes))
        error = "Usuario o contraseña incorrectos"
    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])      # POST + token CSRF: otra página no puede cerrar la sesión
def logout():
    evento("LOGOUT")
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def inicio():
    u = requiere_sesion()
    if not u:
        return redirect(url_for("login"))
    return render_template("inicio.html", u=u)


# 1. SQL Injection corregido -----------------------------------------------------------
@app.route("/buscar")
def buscar():
    u = requiere_sesion()
    if not u:
        return redirect(url_for("login"))
    if u["rol"] not in ("docente", "escolares"):  # alumnos y admin no necesitan el directorio
        evento("ACCESO_DENEGADO", "WARNING", recurso="directorio de alumnos", rol=u["rol"])
        abort(403)
    q = request.args.get("q", "")[:50]
    revisar_entrada("q", q)
    # SEGURO: el valor viaja como parámetro; SQLite nunca lo interpreta como código SQL.
    # Además se escapan los comodines de LIKE (% y _) para que el usuario no pueda
    # convertir su búsqueda en "traer todo" (hallazgo de ZAP en la primera validación).
    q_like = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    filas = db().execute(
        "SELECT matricula, nombre, carrera FROM alumnos WHERE nombre LIKE ? ESCAPE '\\'",
        (f"%{q_like}%",),
    ).fetchall()
    if u["rol"] == "docente":                     # el docente solo ve a sus alumnos asignados
        propios = alumnos_asignados(u)
        filas = [f for f in filas if f["matricula"] in propios]
    return render_template("buscar.html", u=u, q=q, filas=filas, error=None)


# 2. XSS corregido ----------------------------------------------------------------------
@app.route("/avisos", methods=["GET", "POST"])
def avisos():
    u = requiere_sesion()
    if not u:
        return redirect(url_for("login"))
    if request.method == "POST":
        contenido = request.form.get("contenido", "").strip()[:500]
        revisar_entrada("contenido", contenido)
        if contenido:
            db().execute("INSERT INTO avisos (autor, contenido) VALUES (?, ?)", (u["usuario"], contenido))
            db().commit()
            evento("AVISO_PUBLICADO", longitud=len(contenido))
        return redirect(url_for("avisos"))
    lista = db().execute("SELECT * FROM avisos ORDER BY id DESC").fetchall()
    return render_template("avisos.html", u=u, avisos=lista)


# 3. IDOR / BOLA corregido ----------------------------------------------------------------
@app.route("/alumno/<matricula>")
def expediente(matricula):
    u = requiere_sesion()
    if not u:
        return redirect(url_for("login"))
    validar_matricula(matricula)
    if not puede_ver_alumno(u, matricula):
        evento("ACCESO_DENEGADO", "ALERT", recurso=f"expediente {matricula}",
               propio=u["matricula"], rol=u["rol"])
        abort(403)
    a = db().execute("SELECT * FROM alumnos WHERE matricula = ?", (matricula,)).fetchone()
    if not a:
        abort(404)
    evento("EXPEDIENTE_CONSULTADO", recurso=matricula)
    return render_template("expediente.html", u=u, a=a)


@app.route("/api/alumnos/<matricula>/calificaciones")
def api_calificaciones(matricula):
    u = usuario_actual()
    if not u:
        evento("NO_AUTENTICADO", "WARNING")
        return jsonify(error="no autenticado"), 401
    if not MATRICULA_RE.fullmatch(matricula):
        evento("ENTRADA_INVALIDA", "WARNING", campo="matricula", valor=matricula[:40])
        return jsonify(error="matrícula inválida"), 400
    if not puede_ver_alumno(u, matricula):
        evento("ACCESO_DENEGADO", "ALERT", recurso=f"calificaciones {matricula}",
               propio=u["matricula"], rol=u["rol"])
        return jsonify(error="prohibido"), 403
    filas = db().execute("SELECT materia, calificacion FROM calificaciones WHERE matricula = ?",
                         (matricula,)).fetchall()
    return jsonify(matricula=matricula, calificaciones=[dict(f) for f in filas])


# Administración: gestiona cuentas, nunca ve expedientes ------------------------------------
@app.route("/admin/usuarios")
def admin_usuarios():
    u = requiere_sesion()
    if not u:
        return redirect(url_for("login"))
    if u["rol"] != "admin":
        evento("ACCESO_DENEGADO", "ALERT", recurso="administración de usuarios", rol=u["rol"])
        abort(403)
    cuentas = db().execute("SELECT usuario, rol, nombre FROM usuarios ORDER BY rol, usuario").fetchall()
    evento("ADMIN_CONSULTA", "WARNING", recurso="lista de usuarios")   # toda acción de admin queda registrada
    return render_template("admin.html", u=u, cuentas=cuentas)


# ------------------------------------------------------------------ errores sin detalles internos
@app.errorhandler(CSRFError)
def csrf_rechazado(e):
    evento("CSRF_RECHAZADO", "ALERT", motivo=e.description)
    return "Solicitud rechazada: falta el token CSRF o no es válido", 400


@app.errorhandler(400)
def e400(_e):
    return "Solicitud inválida", 400


@app.errorhandler(403)
def e403(_e):
    return "Acceso denegado", 403


@app.errorhandler(404)
def e404(_e):
    evento("RECURSO_NO_ENCONTRADO", "INFO")
    return "No encontrado", 404


@app.errorhandler(500)
def e500(_e):
    evento("ERROR_INTERNO", "ERROR")
    return "Error interno", 500


class ServidorSinVersion(WSGIRequestHandler):
    """El servidor de desarrollo anuncia 'Werkzeug/x.y Python/x.y' en la cabecera Server.
    Se reemplaza por un nombre genérico para no revelar versiones.
    En producción se usaría Gunicorn detrás de Nginx con server_tokens off."""

    def version_string(self):
        return "PortalEscolar"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False, request_handler=ServidorSinVersion)
