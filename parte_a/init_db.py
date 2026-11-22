"""
Crea la base de datos de laboratorio del Campus Las Torres (SQLite).

Todos los datos son FICTICIOS. Las contraseñas de las cuentas de prueba se
generan al azar en cada ejecución y se guardan en instance/credenciales_lab.json,
que está en .gitignore para no publicarlas en GitHub.

Uso:
    python parte_a/init_db.py
"""
import json
import secrets
import sqlite3
from pathlib import Path

from werkzeug.security import generate_password_hash

BASE = Path(__file__).resolve().parent
INSTANCE = BASE / "instance"
DB_PATH = INSTANCE / "campus.db"
CRED_PATH = INSTANCE / "credenciales_lab.json"

# usuario, rol, matrícula (solo alumnos), nombre
CUENTAS = [
    ("al_laura", "alumno", "AL00000001", "Laura Gómez (ficticia)"),
    ("al_diego", "alumno", "AL00000002", "Diego Ramírez (ficticio)"),
    ("doc_maria", "docente", None, "María Torres (ficticia)"),
    ("se_carlos", "escolares", None, "Carlos Peña (ficticio)"),
]

ALUMNOS = [
    # matrícula, nombre, carrera, CURP ficticia, teléfono ficticio, beca
    ("AL00000001", "Laura Gómez", "Ing. en Desarrollo de Software", "FICT010101MNLGMR01", "81-0000-0001", "Beca académica 40%"),
    ("AL00000002", "Diego Ramírez", "Lic. en Administración", "FICT020202HNLRMD02", "81-0000-0002", "Sin beca"),
    ("AL00000003", "Ana Salinas", "Preparatoria (menor de edad)", "FICT080303MNLSLN03", "81-0000-0003", "Beca deportiva 25%"),
    ("AL00000004", "Pedro Cantú", "Ing. Industrial", "FICT030404HNLCNP04", "81-0000-0004", "Sin beca"),
]

CALIFICACIONES = [
    ("AL00000001", "Ciberseguridad", 95), ("AL00000001", "Bases de datos", 88),
    ("AL00000002", "Contabilidad", 72), ("AL00000002", "Finanzas", 65),
    ("AL00000003", "Matemáticas I", 90), ("AL00000004", "Estadística", 81),
]


def crear():
    INSTANCE.mkdir(exist_ok=True)
    if DB_PATH.exists():
        DB_PATH.unlink()
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.executescript(
        """
        CREATE TABLE usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            rol TEXT NOT NULL CHECK (rol IN ('alumno','docente','escolares')),
            matricula TEXT,
            nombre TEXT NOT NULL
        );
        CREATE TABLE alumnos (
            matricula TEXT PRIMARY KEY,
            nombre TEXT NOT NULL,
            carrera TEXT NOT NULL,
            curp TEXT NOT NULL,
            telefono TEXT NOT NULL,
            beca TEXT NOT NULL
        );
        CREATE TABLE calificaciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            matricula TEXT NOT NULL REFERENCES alumnos(matricula),
            materia TEXT NOT NULL,
            calificacion INTEGER NOT NULL
        );
        CREATE TABLE avisos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            autor TEXT NOT NULL,
            contenido TEXT NOT NULL,
            fecha TEXT DEFAULT (datetime('now','localtime'))
        );
        """
    )
    credenciales = {}
    for usuario, rol, matricula, nombre in CUENTAS:
        pwd = secrets.token_urlsafe(9)
        credenciales[usuario] = pwd
        cur.execute(
            "INSERT INTO usuarios (usuario, password_hash, rol, matricula, nombre) VALUES (?,?,?,?,?)",
            (usuario, generate_password_hash(pwd), rol, matricula, nombre),
        )
    cur.executemany("INSERT INTO alumnos VALUES (?,?,?,?,?,?)", ALUMNOS)
    cur.executemany("INSERT INTO calificaciones (matricula, materia, calificacion) VALUES (?,?,?)", CALIFICACIONES)
    cur.execute("INSERT INTO avisos (autor, contenido) VALUES (?, ?)",
                ("se_carlos", "Recuerden que las reinscripciones cierran el viernes."))
    con.commit()
    con.close()
    CRED_PATH.write_text(json.dumps(credenciales, indent=2), encoding="utf-8")
    print(f"Base de datos creada en {DB_PATH}")
    print(f"Contraseñas de laboratorio en {CRED_PATH} (no se suben a GitHub)")


if __name__ == "__main__":
    crear()
