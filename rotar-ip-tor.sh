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
echo "Reiniciando ${TOR_NAME}..."
docker restart "${TOR_NAME}" >/dev/null
elapsed=0
while [ "$elapsed" -lt "$MAX_WAIT_HEALTH" ]; do
  st=$(docker inspect --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}" "${TOR_NAME}" 2>/dev/null || echo "unknown")
  [ "$st" = "healthy" ] || [ "$st" = "running" ] && break
  sleep 2; elapsed=$((elapsed + 2))
done
NEW_IP="no_verificada"
for i in 1 2 3 4; do
  ip_try=$(check_exit_ip "$(get_tor_ip)")
  if [ -n "$ip_try" ]; then NEW_IP="$ip_try"; break; fi
  sleep 2
done
echo "IP de salida actual: ${NEW_IP}"
[ -n "$OLD_EXIT_IP" ] && [ "$NEW_IP" != "no_verificada" ] && [ "$OLD_EXIT_IP" != "$NEW_IP" ] && echo "Cambio verificado: ${OLD_EXIT_IP} -> ${NEW_IP}"
echo "MaxCircuitDirtiness configurado: ${MAX_CIRCUIT_DIRTINESS} segundos"
echo "Timestamp final: $(date '+%Y-%m-%d %H:%M:%S')"
