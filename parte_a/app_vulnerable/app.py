"""
Portal Escolar del Campus Las Torres — VERSIÓN VULNERABLE (solo laboratorio).

Contiene a propósito tres vulnerabilidades para la Parte A:
  1. SQL Injection      -> /buscar          (consulta armada con f-string)
  2. XSS (reflejado y almacenado) -> /buscar y /avisos (filtro |safe en plantillas)
  3. IDOR / BOLA        -> /alumno/<matricula> y /api/alumnos/<matricula>/calificaciones
                           (solo verifica que haya sesión, no a quién pertenece el recurso)

NO EXPONER FUERA DE 127.0.0.1. Ejecutar con:
    python parte_a/app_vulnerable/app.py      (puerto 5000)
"""
import os
import sqlite3
from pathlib import Path

from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

DB_PATH = Path(__file__).resolve().parent.parent / "instance" / "campus.db"

app = Flask(__name__, template_folder=str(Path(__file__).resolve().parent / "templates"))
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)


@app.context_processor
def version():
    return {"version": "VULNERABLE"}


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


def usuario_actual():
    if "uid" not in session:
        return None
    return db().execute("SELECT * FROM usuarios WHERE id = ?", (session["uid"],)).fetchone()


@app.route("/salud")
def salud():
    return jsonify(estado="ok", version="vulnerable")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = db().execute("SELECT * FROM usuarios WHERE usuario = ?",
                         (request.form.get("usuario", ""),)).fetchone()
        if u and check_password_hash(u["password_hash"], request.form.get("password", "")):
            session["uid"] = u["id"]
            return redirect(url_for("inicio"))
        error = "Usuario o contraseña incorrectos"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def inicio():
    u = usuario_actual()
    if not u:
        return redirect(url_for("login"))
    return render_template("inicio.html", u=u)


# ---------------------------------------------------------------- 1. SQL Injection
@app.route("/buscar")
def buscar():
    u = usuario_actual()
    if not u:
        return redirect(url_for("login"))
    q = request.args.get("q", "")
    # VULNERABLE: la entrada del usuario se concatena directamente en la consulta.
    sql = f"SELECT matricula, nombre, carrera FROM alumnos WHERE nombre LIKE '%{q}%'"
    try:
        filas = db().execute(sql).fetchall()
        error = None
    except sqlite3.Error as e:
        filas, error = [], f"Error de base de datos: {type(e).__module__}.{type(e).__name__}: {e}"  # VULNERABLE: filtra detalles internos
    return render_template("buscar.html", u=u, q=q, filas=filas, error=error, sql=sql)


# ---------------------------------------------------------------- 2. XSS almacenado
@app.route("/avisos", methods=["GET", "POST"])
def avisos():
    u = usuario_actual()
    if not u:
        return redirect(url_for("login"))
    if request.method == "POST":
        db().execute("INSERT INTO avisos (autor, contenido) VALUES (?, ?)",
                     (u["usuario"], request.form.get("contenido", "")))
        db().commit()
        return redirect(url_for("avisos"))
    lista = db().execute("SELECT * FROM avisos ORDER BY id DESC").fetchall()
    return render_template("avisos.html", u=u, avisos=lista)


# ---------------------------------------------------------------- 3. IDOR / BOLA
@app.route("/alumno/<matricula>")
def expediente(matricula):
    u = usuario_actual()
    if not u:
        return redirect(url_for("login"))
    # VULNERABLE: no se verifica que el expediente pertenezca al usuario.
    a = db().execute("SELECT * FROM alumnos WHERE matricula = ?", (matricula,)).fetchone()
    if not a:
        return "No encontrado", 404
    return render_template("expediente.html", u=u, a=a)


@app.route("/api/alumnos/<matricula>/calificaciones")
def api_calificaciones(matricula):
    u = usuario_actual()
    if not u:
        return jsonify(error="no autenticado"), 401
    # VULNERABLE: cualquier usuario autenticado obtiene las calificaciones de cualquier matrícula.
    filas = db().execute("SELECT materia, calificacion FROM calificaciones WHERE matricula = ?",
                         (matricula,)).fetchall()
    return jsonify(matricula=matricula, calificaciones=[dict(f) for f in filas])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
