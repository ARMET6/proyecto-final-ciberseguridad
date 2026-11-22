"""Pruebas unitarias de las correcciones (ejecutar: python -m pytest parte_a/tests -v)."""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

BASE = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def cliente():
    subprocess.run([sys.executable, str(BASE / "init_db.py")], check=True, capture_output=True)
    spec = importlib.util.spec_from_file_location("app_segura", BASE / "app_segura" / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.app.testing = True
    creds = json.loads((BASE / "instance" / "credenciales_lab.json").read_text())
    return mod.app, creds


def entrar(app, creds, usuario):
    c = app.test_client()
    r = c.post("/login", data={"usuario": usuario, "password": creds[usuario]})
    assert r.status_code == 302
    return c


def test_sqli_union_no_filtra_usuarios(cliente):
    app, creds = cliente
    c = entrar(app, creds, "doc_maria")
    r = c.get("/buscar", query_string={"q": "x' UNION SELECT usuario, rol, password_hash FROM usuarios--"})
    assert r.status_code == 200 and b"al_laura" not in r.data and b"scrypt" not in r.data


def test_busqueda_legitima_funciona(cliente):
    app, creds = cliente
    r = entrar(app, creds, "doc_maria").get("/buscar", query_string={"q": "Laura"})
    assert b"AL00000001" in r.data


def test_xss_almacenado_se_escapa(cliente):
    app, creds = cliente
    c = entrar(app, creds, "doc_maria")
    c.post("/avisos", data={"contenido": "<script>alert(1)</script>"})
    r = c.get("/avisos")
    assert b"<script>alert(1)</script>" not in r.data and b"&lt;script&gt;" in r.data
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]


def test_idor_alumno_no_ve_a_otro(cliente):
    app, creds = cliente
    c = entrar(app, creds, "al_laura")
    assert c.get("/alumno/AL00000001").status_code == 200
    assert c.get("/alumno/AL00000002").status_code == 403
    assert c.get("/api/alumnos/AL00000003/calificaciones").status_code == 403


def test_docente_si_consulta_calificaciones(cliente):
    app, creds = cliente
    assert entrar(app, creds, "doc_maria").get("/api/alumnos/AL00000003/calificaciones").status_code == 200


def test_matricula_invalida(cliente):
    app, creds = cliente
    assert entrar(app, creds, "al_laura").get("/alumno/..%2F..%2Fetc").status_code in (400, 404)


def test_comodin_like_no_trae_todo(cliente):
    app, creds = cliente
    r = entrar(app, creds, "doc_maria").get("/buscar", query_string={"q": "%"})
    assert b"AL0000000" not in r.data
