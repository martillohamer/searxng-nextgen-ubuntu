#!/usr/bin/env bash
set -euo pipefail

DEFAULT_PROYECTO="/mnt/c/Users/astur/Desktop/tubuntu-searxng-nextgen"
if SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" && [ -f "$SCRIPT_DIR/docker-compose.yml" ]; then
  PROYECTO="$SCRIPT_DIR"
else
  PROYECTO="$DEFAULT_PROYECTO"
fi

cd "$PROYECTO"

echo "=========================================="
echo "   INICIANDO CLÚSTER SEARVGA // T-800     "
echo "=========================================="

docker compose up -d

READY=0
echo -n "Esperando a que el interfaz (:8890/health) esté listo"
for _ in {1..15}; do
  if curl -fsS "http://127.0.0.1:8890/health" | grep -q '"status"'; then
    echo " [OK]"
    READY=1
    break
  fi
  echo -n "."
  sleep 1
done

if [ "$READY" -ne 1 ]; then
  echo " [TIMEOUT]"
  docker ps --filter "name=searvga" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
  echo "Aviso: :8890/health no respondió tras 15s; revisa 'docker compose logs -n 30'."
  exit 1
fi

echo ""
docker ps --filter "name=searvga" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo ""
echo "SearVGA operativo en: http://127.0.0.1:8890"
