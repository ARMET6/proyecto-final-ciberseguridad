# Procedimiento de respuesta a incidentes · Ransomware en el Campus Las Torres

**Escenario (del avance):** en periodo de inscripciones, un administrativo abre un correo de phishing ("aviso de pago").
El malware usa sus credenciales para llegar a VM-FS01 y a la base de datos de VM-APP01 y cifra expedientes,
carpetas de Servicios Escolares y Finanzas.

**Responsables:** Coordinador de TI (líder del incidente) · Administradores de infraestructura (GG_TI_Admins)
· Dirección del campus (decisiones y comunicación) · Jurídico (obligaciones LFPDPPP).

Leyenda: ✅ **Probado** en el laboratorio de este proyecto · 📋 **Recomendado**, no implementado.

## 1. Detección

| Acción | Estado |
|---|---|
| Alertas de la aplicación: `ACCESO_DENEGADO`, `LOGIN_FALLIDO`, `CUENTA_BLOQUEADA`, `ENTRADA_SOSPECHOSA` en `seguridad.log` | ✅ Actividad 5 |
| Reglas de correlación (fuerza bruta, enumeración IDOR, escaneo automatizado) con `analisis_logs.py` | ✅ Actividad 5 |
| Contadores y registros `FW-DROP` del firewall cuando un equipo intenta llegar a servidores o respaldos | ✅ Parte B |
| Wazuh en VM-MON01: alerta por cientos de archivos renombrados por minuto en VM-FS01 (FIM) | 📋 |
| Reporte de usuarios: archivos con extensión extraña o nota de rescate → mesa de ayuda | 📋 |

**Criterio para declarar incidente:** nota de rescate, cifrado masivo de archivos o alerta de Wazuh de nivel alto.

## 2. Análisis

| Acción | Estado |
|---|---|
| Identificar el equipo y la cuenta de origen con las bitácoras (IP, usuario, ruta, hora) | ✅ formato JSON de la bitácora |
| Determinar el alcance: qué VLAN, qué servidores y qué carpetas están cifradas | 📋 |
| Revisar si hubo exfiltración (conexiones salientes grandes en OPNsense) → posible vulneración de datos de menores | 📋 |
| Confirmar que SRV-BK01 y la copia de la nube están intactos (fuera del dominio, inmutable) | 📋 |
| Clasificar severidad: crítica si afecta expedientes, finanzas o datos sensibles | 📋 |

## 3. Contención

| Acción | Estado |
|---|---|
| Segmentación: un equipo de laboratorio infectado **no** alcanza SMB 445 de VM-FS01 ni el puerto 8007 de SRV-BK01 | ✅ Parte B (24/24 flujos) |
| Aislar la VLAN afectada con una regla `drop` en el firewall (ver comando abajo) | ✅ probado en el namespace `fw` |
| Deshabilitar la cuenta comprometida y cerrar sus sesiones (`samba-tool user disable`) | 📋 |
| Apagar o desconectar la VM afectada; tomar instantánea para análisis forense antes de limpiar | 📋 |
| No pagar el rescate; preservar la nota y muestras | 📋 |

Comando de aislamiento de emergencia (probado; ejemplo con la VLAN 20 de administrativos):

```bash
sudo bash parte_b/laboratorio_red.sh aislar adm     # inserta reglas drop "IR-AISLAR-adm" al inicio de la cadena forward
sudo bash parte_b/laboratorio_red.sh desaislar      # elimina solo esas reglas cuando el equipo ya está limpio
```

Resultado en `evidencias/parte_b/aislamiento_ir.txt`: con la VLAN 20 aislada, el administrativo ya no llega a
VM-FS01:445, mientras TI conserva su acceso SSH para investigar.

## 4. Recuperación

| Acción | Estado |
|---|---|
| Restaurar archivos desde el respaldo y comprobar la huella SHA-256 | ✅ avance (Evidencia 12) |
| Datos protegidos con cifrado LUKS2 si se roba el disco | ✅ avance (Evidencias 7-9) |
| Acceso administrativo con MFA (SSH + TOTP) | ✅ avance (Evidencia 11) |
| Restaurar VMs completas desde SRV-BK01 (RTO 8 h servicios críticos) | 📋 |
| Si SRV-BK01 fue alcanzado: restaurar desde la copia inmutable en la nube | 📋 |
| Cambiar contraseñas de las cuentas involucradas y de cuentas privilegiadas | 📋 |
| Desplegar la versión corregida de las aplicaciones (sin SQLi/XSS/IDOR) | ✅ Parte A |

## 5. Verificación

| Acción | Estado |
|---|---|
| Repetir `pruebas_seguridad.py` y ZAP contra la app restaurada: 0 vulnerabilidades High | ✅ Parte A |
| Repetir `laboratorio_red.sh probar`: las reglas siguen aplicadas (24/24) | ✅ Parte B |
| Comparar huellas SHA-256 de archivos restaurados contra el inventario | ✅ avance |
| Monitoreo reforzado 30 días sobre las cuentas y equipos afectados | 📋 |
| Notificar a titulares afectados si la vulneración afecta significativamente sus derechos (LFPDPPP) | 📋 |
| Reunión de lecciones aprendidas y actualización de este procedimiento | 📋 |

## Responsables, tiempos y criterios de cierre

Objetivos tomados del avance del proyecto: **RTO** de 8 horas para servicios críticos y 48 horas para el resto;
**RPO** de 1 hora para borrados accidentales y 24 horas ante una falla de servidor.

| Etapa | Responsable | Acción principal | Tiempo objetivo | Criterio para pasar a la siguiente etapa |
|---|---|---|---|---|
| Detección | Monitoreo / TI (Wazuh, bitácoras) | Confirmar la alerta y abrir el registro del incidente | 15 min desde la alerta | Incidente registrado con hora, equipo y cuenta |
| Análisis | Coordinador de TI | Identificar equipos, cuentas, VLAN y datos afectados | 1 h | Alcance documentado; respaldos revisados y sin compromiso |
| Contención | Administradores de red | Aislar la VLAN o el equipo (`aislar <segmento>`), deshabilitar la cuenta | 30 min tras el análisis | Contadores del firewall sin tráfico nuevo del origen |
| Recuperación | Administradores de sistemas | Restaurar desde SRV-BK01 o la nube, en orden de prioridad | Dentro del RTO (8 h críticos) | Huellas SHA-256 iguales; servicios en línea |
| Verificación | TI y responsables de cada sistema | Repetir pruebas de seguridad y conectividad | 2 h tras la restauración | 0 alertas High en ZAP, 30/30 flujos de red, usuarios validan |

Todas las decisiones, responsables y horas se anotan en el registro del incidente para la reunión de lecciones aprendidas.
Los tiempos objetivo de cada etapa son una propuesta del equipo; el RTO y el RPO vienen del avance.
