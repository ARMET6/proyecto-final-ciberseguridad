# Guía de OWASP ZAP (escritorio) para las capturas del informe

El script `parte_a/zap/escaneo_zap.py` hace todo esto de forma automática, pero el informe necesita
capturas de pantalla de ZAP. Estos son los pasos en la versión de escritorio.

## 1. Configuración (Actividad 1)

1. Ejecuta `python parte_a/init_db.py` y levanta las dos apps (puertos 5000 y 5001).
2. Abre ZAP → *Manual Explore* → URL `http://127.0.0.1:5000` → *Launch Browser* (Firefox o Chrome con el proxy de ZAP).
3. En ese navegador inicia sesión como `doc_maria` y recorre: Buscar alumnos (busca "Laura"), Avisos (publica uno),
   y como `al_laura`: Mi expediente y Mis calificaciones (API).
4. En el árbol *Sites* clic derecho en `http://127.0.0.1:5000` → *Include in Context* → *New Context*.
   En *Exclude from Context* agrega `http://127.0.0.1:5000/logout.*` (si no, el escaneo cierra tu sesión).

📸 Captura 1: árbol *Sites* con los endpoints descubiertos y el contexto creado.

## 2. Escaneo (Actividad 2)

1. *Analyse → Scan Policy Manager → Default Policy → Injection*: sube **SQL Injection** y
   **SQL Injection - SQLite** a *Attack strength: Insane* y *Alert threshold: Low*.
   Con la fuerza por defecto ZAP no prueba suficientes variantes dentro del `LIKE '%...%'` de la búsqueda.
2. Clic derecho en el sitio → *Attack → Spider*, después *Attack → Active Scan* con esa política.
3. Pestaña *Alerts*.

📸 Captura 2: pestaña *Alerts* de la versión vulnerable con Cross Site Scripting (Persistent),
Cross Site Scripting (Reflected) y SQL Injection - SQLite en rojo (riesgo High).
📸 Captura 3: detalle de la alerta SQL Injection - SQLite (parámetro `q`, ataque `case randomblob(...)`).

> **Falso positivo a reportar:** ZAP también marca SQLi en `POST /avisos`. Ese INSERT ya usa parámetros (`?`);
> la alerta es por tiempo y aparece porque la página de avisos tarda más a medida que ZAP publica cientos
> de avisos. Se documenta como falso positivo después de revisar el código.

> **Limitación de la herramienta:** ZAP **no detecta IDOR/BOLA**, porque no sabe qué datos le pertenecen a cada
> usuario. Esa vulnerabilidad se demuestra con prueba manual (`pruebas_seguridad.py` o el navegador).

## 3. Validación (Actividad 4)

Repite los pasos 1 y 2 con `http://127.0.0.1:5001`.

📸 Captura 4: pestaña *Alerts* de la versión corregida **sin alertas High**.
Quedan alertas Medium/Low que se reportan como riesgos pendientes:
*Absence of Anti-CSRF Tokens*, *CSP: style-src unsafe-inline* y *Server Leaks Version Information*.

## 4. Reporte

*Report → Generate Report → Traditional HTML*. Guarda `evidencias/zap_vulnerable.html` y `evidencias/zap_corregida.html`.
