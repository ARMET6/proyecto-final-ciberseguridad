#!/usr/bin/env bash
# =============================================================================
# Laboratorio de red del Campus Las Torres — Parte B, opción A (Seguridad de red)
#
# Crea una red virtual con "network namespaces" de Linux (no necesita VMs extra):
# cada VLAN del diseño es un namespace y un namespace "fw" hace de firewall
# (OPNsense en el diseño real) que enruta entre ellas. Luego:
#   1) escanea con Nmap la red SIN firewall (red plana, situación inicial),
#   2) aplica reglas_campus.nft,
#   3) vuelve a escanear y ejecuta la matriz de pruebas de conectividad.
#
# Requiere Linux (Kali/Debian/Ubuntu) con: iproute2, nftables, nmap, python3. Ejecutar con sudo:
#     sudo bash parte_b/laboratorio_red.sh todo
# Subcomandos: crear | sin_firewall | con_firewall | escanear <etiqueta> | probar | contadores |
#             aislar <segmento> | desaislar | destruir | todo
# Todo ocurre dentro de namespaces aislados: no toca la red real del equipo.
# =============================================================================
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$DIR/../evidencias/parte_b}"
mkdir -p "$OUT"
SEGMENTOS=(srv bk adm lab ti inet)
declare -A RED=( [srv]=10.10.10 [bk]=10.10.15 [adm]=10.10.20 [lab]=10.10.40 [ti]=10.10.99 [inet]=203.0.113 )
declare -A HOST=( [srv]=10 [bk]=10 [adm]=50 [lab]=50 [ti]=50 [inet]=10 )
declare -A NOMBRE=( [srv]="VLAN10-Servidores" [bk]="VLAN15-Respaldos" [adm]="VLAN20-Administrativos" \
                    [lab]="VLAN40-Laboratorios" [ti]="VLAN99-Gestion-TI" [inet]="Internet-simulado" )
PUERTOS="22,53,80,88,389,443,445,464,636,1514,1515,3389,5432,8006,8007"

ns() { ip netns exec "$@"; }

crear() {
  destruir >/dev/null 2>&1 || true
  ip netns add fw
  ns fw sysctl -qw net.ipv4.ip_forward=1
  ns fw ip link set lo up
  for s in "${SEGMENTOS[@]}"; do
    ip netns add "$s"
    ip link add "v-$s" type veth peer name eth0 netns "$s"
    ip link set "v-$s" netns fw
    ns fw ip addr add "${RED[$s]}.1/24" dev "v-$s"
    ns fw ip link set "v-$s" up
    ns "$s" ip link set lo up
    ns "$s" ip addr add "${RED[$s]}.${HOST[$s]}/24" dev eth0
    ns "$s" ip link set eth0 up
    ns "$s" ip route add default via "${RED[$s]}.1"
  done
  # Segundo equipo de la VLAN 20: recepción, que no necesita las carpetas de VM-FS01
  ns adm ip addr add 10.10.20.60/24 dev eth0
  # Servidores de la VLAN 10 (cuatro VMs del host SRV-HV01)
  for h in 20 30 40; do ns srv ip addr add "10.10.10.$h/24" dev eth0; done
  ns srv python3 "$DIR/servicios_simulados.py" VM-DC01 10.10.10.10:22 10.10.10.10:53 10.10.10.10:88 \
     10.10.10.10:389 10.10.10.10:445 10.10.10.10:464 10.10.10.10:636 \
     10.10.10.10:udp/53 10.10.10.10:udp/88 10.10.10.10:udp/464 >/dev/null 2>&1 &
  ns srv python3 "$DIR/servicios_simulados.py" VM-FS01 10.10.10.20:22 10.10.10.20:445 \
     10.10.10.20:udp/137 >/dev/null 2>&1 &
  ns srv python3 "$DIR/servicios_simulados.py" VM-APP01 10.10.10.30:22 10.10.10.30:443 10.10.10.30:5432 >/dev/null 2>&1 &
  ns srv python3 "$DIR/servicios_simulados.py" VM-MON01 10.10.10.40:22 10.10.10.40:443 10.10.10.40:1514 \
     10.10.10.40:1515 >/dev/null 2>&1 &
  ns bk  python3 "$DIR/servicios_simulados.py" SRV-BK01 10.10.15.10:22 10.10.15.10:8007 >/dev/null 2>&1 &
  ns inet python3 "$DIR/servicios_simulados.py" Internet 203.0.113.10:80 203.0.113.10:443 203.0.113.10:22 >/dev/null 2>&1 &
  sleep 1
  echo "Red creada:"
  for s in "${SEGMENTOS[@]}"; do printf "  %-24s %s.0/24\n" "${NOMBRE[$s]}" "${RED[$s]}"; done
  echo "  (VLAN 20 con dos equipos: 10.10.20.50 Servicios Escolares y 10.10.20.60 recepción)"
}

sin_firewall() { ns fw nft flush ruleset; echo "Firewall SIN reglas: el campus es una red plana."; }

con_firewall() {
  ns fw nft -f "$DIR/reglas_campus.nft"
  ns fw nft list ruleset > "$OUT/reglas_aplicadas.txt"
  echo "Reglas de reglas_campus.nft aplicadas (copia en $OUT/reglas_aplicadas.txt)."
}

escanear() {
  local etiqueta="$1" f="$OUT/nmap_${1}.txt"
  : > "$f"
  for origen in lab adm ti; do
    {
      echo "##### Escaneo desde ${NOMBRE[$origen]} (${RED[$origen]}.${HOST[$origen]}) · $etiqueta"
      echo "##### nmap -sT -Pn -n --max-retries 1 --host-timeout 30s -p $PUERTOS 10.10.10.10,20,30,40 10.10.15.10"
      ns "$origen" nmap -sT -Pn -n --max-retries 1 --host-timeout 30s -p "$PUERTOS" \
         10.10.10.10,20,30,40 10.10.15.10 | grep -vE "^(Starting|Nmap done)"
      echo
    } >> "$f"
  done
  # UDP: DNS, Kerberos y kpasswd de VM-DC01 y NetBIOS de VM-FS01, desde laboratorios
  {
    echo "##### Escaneo UDP desde ${NOMBRE[lab]} · $etiqueta"
    echo "##### nmap -sU -Pn -n --max-retries 1 -p 53,88,137,464 10.10.10.10,20"
    ns lab nmap -sU -Pn -n --max-retries 1 -p 53,88,137,464 10.10.10.10,20 | grep -vE "^(Starting|Nmap done)"
    echo
  } >> "$f"
  echo "Resumen de puertos ABIERTOS por origen ($etiqueta):"
  python3 - "$f" <<'PY'
import re, sys
bloque = None
for l in open(sys.argv[1]):
    if l.startswith("##### Escaneo"):
        bloque = l.split("desde ")[1].split(" (")[0].split(" ·")[0].strip()
        if "UDP" in l: bloque += " (UDP)"
        print(f"  {bloque}:"); host = None
    m = re.match(r"Nmap scan report for (\S+)", l)
    if m: host = m.group(1)
    m = re.match(r"(\d+)/(tcp|udp)\s+open\s", l)
    if m: print(f"      {host}:{m.group(1)}" + ("/udp" if m.group(2) == "udp" else ""))
PY
  echo "Salida completa: $f"
}

# Matriz de pruebas: origen | destino | puerto | esperado | justificación
PRUEBAS=(
  "adm|10.10.10.10|389|PERMITIDO|Administrativo inicia sesión en el dominio (R01)"
  "adm|10.10.10.20|445|PERMITIDO|Administrativo abre carpetas en VM-FS01 (R02)"
  "adm|10.10.10.30|443|PERMITIDO|Administrativo usa las aplicaciones web (R03)"
  "adm|10.10.10.30|5432|BLOQUEADO|Nadie fuera de servidores habla directo con PostgreSQL"
  "adm|10.10.10.20|22|BLOQUEADO|SSH solo desde Gestión TI"
  "adm|10.10.15.10|8007|BLOQUEADO|Usuarios no alcanzan el servidor de respaldos (B02)"
  "adm|203.0.113.10|443|PERMITIDO|Navegación web (R05)"
  "adm|10.10.10.10|udp/53|PERMITIDO|DNS por UDP hacia el controlador de dominio (R01u)"
  "adm@10.10.20.60|10.10.10.10|389|PERMITIDO|Recepción sí inicia sesión en el dominio (R01)"
  "adm@10.10.20.60|10.10.10.20|445|BLOQUEADO|Recepción no necesita carpetas: sin SMB (B04)"
  "lab|10.10.10.10|88|PERMITIDO|Equipo de laboratorio inicia sesión con Kerberos (R04)"
  "lab|10.10.10.10|udp/53|PERMITIDO|DNS por UDP (R04u)"
  "lab|10.10.10.10|udp/88|PERMITIDO|Kerberos por UDP (R04u)"
  "lab|10.10.10.20|udp/137|BLOQUEADO|Sin NetBIOS/UDP hacia el servidor de archivos (B01)"
  "lab|10.10.10.20|445|BLOQUEADO|Ransomware en laboratorio NO llega a expedientes (B01)"
  "lab|10.10.10.30|443|BLOQUEADO|Laboratorio no usa aplicaciones administrativas"
  "lab|10.10.10.40|1514|BLOQUEADO|Laboratorio no habla con el monitoreo"
  "lab|10.10.15.10|8007|BLOQUEADO|Ransomware NO llega a los respaldos (B02)"
  "lab|10.10.15.10|22|BLOQUEADO|Ni por SSH"
  "lab|203.0.113.10|443|PERMITIDO|Internet para clases (R05)"
  "lab|203.0.113.10|22|BLOQUEADO|Sin SSH saliente desde laboratorios"
  "ti|10.10.10.20|22|PERMITIDO|TI administra servidores por SSH (R06)"
  "ti|10.10.10.40|443|PERMITIDO|TI consulta Wazuh (R06)"
  "ti|10.10.15.10|8007|PERMITIDO|TI administra Proxmox Backup Server (R07)"
  "ti|10.10.10.30|5432|BLOQUEADO|Ni TI entra directo a la base de datos"
  "srv|10.10.15.10|8007|PERMITIDO|Servidores envían su respaldo a SRV-BK01 (R09)"
  "srv|10.10.15.10|22|BLOQUEADO|Un servidor comprometido no puede entrar a BK01 por SSH"
  "bk|203.0.113.10|443|PERMITIDO|SRV-BK01 sube la copia cifrada a la nube (R11)"
  "bk|10.10.10.20|445|BLOQUEADO|El servidor de respaldos no inicia conexiones a servidores"
  "inet|10.10.10.30|443|BLOQUEADO|Internet no entra directo a la red interna"
)

probar() {
  local f="$OUT/pruebas_conectividad.txt" ok=0 total=0
  printf "%-18s %-13s %-8s %-10s %-10s %-3s %s\n" ORIGEN DESTINO PUERTO ESPERADO OBTENIDO OK JUSTIFICACION | tee "$f"
  for p in "${PRUEBAS[@]}"; do
    IFS='|' read -r o d port esp just <<< "$p"
    local nso="${o%%@*}" origen="" proto=tcp num="$port"
    [[ "$o" == *@* ]] && origen="--origen ${o#*@}"
    [[ "$port" == udp/* ]] && { proto=udp; num="${port#udp/}"; }
    if ns "$nso" python3 "$DIR/sonda.py" $proto "$d" "$num" $origen; then got=PERMITIDO; else got=BLOQUEADO; fi
    total=$((total+1)); [[ "$got" == "$esp" ]] && { ok=$((ok+1)); r=SI; } || r=NO
    local etiqueta="$nso"; [[ "$o" == *@* ]] && etiqueta="$nso(${o#*@})"
    printf "%-18s %-13s %-8s %-10s %-10s %-3s %s\n" "$etiqueta" "$d" "$port" "$esp" "$got" "$r" "$just" | tee -a "$f"
  done
  echo "Resultado: $ok de $total pruebas coinciden con lo esperado." | tee -a "$f"
}

contadores() {
  echo "Contadores de bloqueos del firewall:" | tee "$OUT/contadores.txt"
  ns fw nft list counters | grep -E "counter|packets" | tee -a "$OUT/contadores.txt"
}

# Respuesta a incidentes: aislar un segmento completo (p. ej. VLAN 20 con un equipo infectado)
aislar() {
  local seg="${1:?uso: aislar adm|lab|srv|bk|ti}"
  ns fw nft insert rule inet campus forward ip saddr "${RED[$seg]}.0/24" counter drop comment "\"IR-AISLAR-$seg\""
  ns fw nft insert rule inet campus forward ip daddr "${RED[$seg]}.0/24" counter drop comment "\"IR-AISLAR-$seg\""
  echo "Segmento ${NOMBRE[$seg]} aislado (todo su tráfico hacia y desde otras VLANs se descarta)."
}
desaislar() {
  ns fw nft -a list chain inet campus forward | grep -o 'IR-AISLAR.*handle [0-9]*' | awk '{print $NF}' |
    while read -r h; do ns fw nft delete rule inet campus forward handle "$h"; done
  echo "Reglas de aislamiento eliminadas."
}

destruir() {
  for s in "${SEGMENTOS[@]}"; do
    ip netns pids "$s" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$s" 2>/dev/null || true
  done
  ip netns del fw 2>/dev/null || true
}

todo() {
  echo "=== 1. Crear la red del campus ===";             crear
  echo; echo "=== 2. Situación inicial: SIN firewall ==="; sin_firewall; escanear antes; probar > "$OUT/pruebas_sin_firewall.txt" || true
  tail -1 "$OUT/pruebas_sin_firewall.txt"
  echo; echo "=== 3. Aplicar reglas ===";                  con_firewall
  echo; echo "=== 4. Validación: CON firewall ===";        escanear despues; echo; probar; echo; contadores
  echo; echo "Evidencias en: $OUT"
}

[[ $EUID -eq 0 ]] || { echo "Ejecuta con sudo"; exit 1; }
"${1:-todo}" "${@:2}"
