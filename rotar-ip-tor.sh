#!/bin/bash
set -u
TOR_NAME="searvga_tor"
SOCKS_PORT="9150"
MAX_CIRCUIT_DIRTINESS=180
MAX_WAIT_HEALTH=50
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
get_tor_ip() { docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" "${TOR_NAME}" 2>/dev/null | awk "NF {print \$1; exit}"; }
check_exit_ip() { [ -n "$1" ] && python3 "${SCRIPT_DIR}/check_tor_ip.py" "$1" "${SOCKS_PORT}" | head -n 1 | tr -d "[:space:]"; }
echo "=== Rotacion de circuito Tor ==="
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
if ! docker ps --filter "name=^/${TOR_NAME}$" --format "{{.Names}}" | grep -q "^${TOR_NAME}$"; then echo "ERROR: ${TOR_NAME} no esta en ejecucion"; exit 1; fi
OLD_EXIT_IP=$(check_exit_ip "$(get_tor_ip)")
[ -n "$OLD_EXIT_IP" ] && echo "IP de salida anterior: ${OLD_EXIT_IP}"
# Intentar rotar circuito usando NEWNYM via ControlPort interno (sin exponer 9151 al host)
echo "Rotando circuito Tor (NEWNYM) via ControlPort interno..."
# Usar docker exec para conectar al ControlPort del contenedor (9151) que no está mapeado al host
RESPONSE=$(echo -e "AUTHENTICATE \"\"\nsignal NEWNYM\nQUIT" | docker exec -i "${TOR_NAME}" nc -w 5 127.0.0.1 9151 2>&1)
if [ $? -eq 0 ] && echo "$RESPONSE" | grep -q "250"; then
    echo "✅ Señal NEWNYM enviada exitosamente al ControlPort interno del contenedor $TOR_NAME"
else
    echo "⚠️  No se pudo enviar NEWNYM por ControlPort interno; reiniciando servicio Tor..."
    docker restart "${TOR_NAME}" >/dev/null
fi
# Esperar a que el contenedor Tor esté saludable después de la rotación
elapsed=0
MAX_WAIT=60
while [ "$elapsed" -lt "$MAX_WAIT" ]; do
  st=$(docker inspect --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}" "${TOR_NAME}" 2>/dev/null || echo "unknown")
  [ "$st" = "healthy" ] || [ "$st" = "running" ] && break
  sleep 2; elapsed=$((elapsed + 2))
done
# Verificar nueva IP de salida mediante curl a través del proxy SOCKS5
echo ""
echo "=== Verificación de nueva IP de salida ==="
NEW_IP=$(curl -s --socks5 127.0.0.1:${SOCKS_PORT} -m 10 --interface 127.0.0.1 http://ifconfig.me 2>/dev/null || echo "fallo_curl")
echo "IP de salida actual: ${NEW_IP}"
# Mostrar información de circuito actual
echo ""
echo "=== Estado de circuito ==="
echo "MaxCircuitDirtiness configurado: ${MAX_CIRCUIT_DIRTINESS} segundos"
echo "Próxima rotación automática ocurrirá después de este tiempo"
echo ""
echo "=== Rotación de circuito completada ==="
echo "Timestamp final: $(date '+%Y-%m-%d %H:%M:%S')"