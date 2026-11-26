"""Pruebas unitarias de las correcciones (ejecutar: python -m pytest parte_a/tests -v)."""
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

BASE = Path(__file__).resolve().parent.parent
TOKEN_RE = re.compile(rb'name="csrf_token" value="([^"]+)"')


@pytest.fixture(scope="module")
def cliente():
    subprocess.run([sys.executable, str(BASE / "init_db.py")], check=True, capture_output=True)
    spec = importlib.util.spec_from_file_location("app_segura", BASE / "app_segura" / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.app.testing = True
    creds = json.loads((BASE / "instance" / "credenciales_lab.json").read_text())
    return mod.app, creds


def token(c, ruta):
    """Obtiene el token CSRF del formulario de una página."""
    return TOKEN_RE.search(c.get(ruta).data).group(1).decode()


def entrar(app, creds, usuario):
    c = app.test_client()
    r = c.post("/login", data={"usuario": usuario, "password": creds[usuario],
                               "csrf_token": token(c, "/login")})
    assert r.status_code == 302
    return c


# ---- SQL Injection
def test_sqli_union_no_filtra_usuarios(cliente):
    app, creds = cliente
    c = entrar(app, creds, "se_carlos")
    r = c.get("/buscar", query_string={"q": "x' UNION SELECT usuario, rol, password_hash FROM usuarios--"})
    assert r.status_code == 200 and b"al_laura" not in r.data and b"scrypt" not in r.data


def test_busqueda_legitima_funciona(cliente):
    app, creds = cliente
    r = entrar(app, creds, "se_carlos").get("/buscar", query_string={"q": "Laura"})
    assert b"AL00000001" in r.data


def test_comodin_like_no_trae_todo(cliente):
    app, creds = cliente
    r = entrar(app, creds, "se_carlos").get("/buscar", query_string={"q": "%"})
    assert b"AL0000000" not in r.data


# ---- XSS, CSP y cabeceras
def test_xss_almacenado_se_escapa(cliente):
    app, creds = cliente
    c = entrar(app, creds, "doc_maria")
    c.post("/avisos", data={"contenido": "<script>alert(1)</script>", "csrf_token": token(c, "/avisos")})
    r = c.get("/avisos")
    assert b"<script>alert(1)</script>" not in r.data and b"&lt;script&gt;" in r.data


def test_csp_sin_unsafe_inline(cliente):
    app, creds = cliente
    r = entrar(app, creds, "doc_maria").get("/avisos")
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "style-src 'self'" in csp and "unsafe-inline" not in csp
    assert b"<style" not in r.data and b"estilos.css" in r.data


def test_cabecera_server_sin_version():
    spec = importlib.util.spec_from_file_location("app_segura_srv", BASE / "app_segura" / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.ServidorSinVersion.version_string(None) == "PortalEscolar"


# ---- CSRF
def test_csrf_sin_token_se_rechaza(cliente):
    app, creds = cliente
    c = entrar(app, creds, "doc_maria")
    r = c.post("/avisos", data={"contenido": "aviso sin token"})
    assert r.status_code == 400
    assert b"aviso sin token" not in c.get("/avisos").data


def test_csrf_con_token_funciona(cliente):
    app, creds = cliente
    c = entrar(app, creds, "doc_maria")
    r = c.post("/avisos", data={"contenido": "aviso con token", "csrf_token": token(c, "/avisos")})
    assert r.status_code == 302 and b"aviso con token" in c.get("/avisos").data


def test_login_sin_token_se_rechaza(cliente):
    app, creds = cliente
    r = app.test_client().post("/login", data={"usuario": "doc_maria", "password": creds["doc_maria"]})
    assert r.status_code == 400


# ---- IDOR / BOLA y permisos por rol
def test_idor_alumno_no_ve_a_otro(cliente):
    app, creds = cliente
    c = entrar(app, creds, "al_laura")
    assert c.get("/alumno/AL00000001").status_code == 200
    assert c.get("/alumno/AL00000002").status_code == 403
    assert c.get("/api/alumnos/AL00000003/calificaciones").status_code == 403


def test_docente_solo_ve_alumnos_asignados(cliente):
    app, creds = cliente
    c = entrar(app, creds, "doc_maria")                     # asignados: AL00000001 y AL00000003
    assert c.get("/api/alumnos/AL00000003/calificaciones").status_code == 200
    assert c.get("/alumno/AL00000001").status_code == 200
    assert c.get("/alumno/AL00000002").status_code == 403
    assert c.get("/api/alumnos/AL00000004/calificaciones").status_code == 403
    r = c.get("/buscar", query_string={"q": "a"})
    assert b"AL00000001" in r.data and b"AL00000002" not in r.data


def test_escolares_gestiona_todos_los_expedientes(cliente):
    app, creds = cliente
    c = entrar(app, creds, "se_carlos")
    for m in ("AL00000001", "AL00000002", "AL00000003", "AL00000004"):
        assert c.get(f"/alumno/{m}").status_code == 200
    assert c.get("/admin/usuarios").status_code == 403


def test_admin_gestiona_cuentas_sin_ver_expedientes(cliente):
    app, creds = cliente
    c = entrar(app, creds, "admin_ti")
    r = c.get("/admin/usuarios")
    assert r.status_code == 200 and b"doc_maria" in r.data and b"scrypt" not in r.data
    assert c.get("/alumno/AL00000001").status_code == 403
    assert c.get("/buscar").status_code == 403


def test_matricula_invalida(cliente):
    app, creds = cliente
    assert entrar(app, creds, "al_laura").get("/alumno/..%2F..%2Fetc").status_code in (400, 404)
