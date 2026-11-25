#!/usr/bin/env bash
set -euo pipefail

CANONICAL="$HOME/searxng-nextgen-ubuntu"
cd "$CANONICAL"

echo "[1/4] Comprobando Docker..."
docker info >/dev/null 2>&1 || {
  echo "ERROR: Docker no esta activo."
  exit 1
}

echo "[2/4] Levantando stack SEARVGA (tor, core, ui, inspector)..."
docker compose up -d

echo "[3/4] Esperando a la UI (http://127.0.0.1:8890/health)..."
for _ in $(seq 1 25); do
  if curl -fsS --max-time 3 http://127.0.0.1:8890/health 2>/dev/null | grep -q '"status"'; then
    break
  fi
  sleep 1
done

echo "[4/4] Verificando API (categories=general)..."
API_OK=0
for _ in $(seq 1 15); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
    'http://127.0.0.1:8890/api/search?q=Java&format=json&categories=general' || true)
  if [ "$code" = "200" ]; then
    API_OK=1
    break
  fi
  sleep 2
done

docker compose ps

if [ "$API_OK" -ne 1 ]; then
  echo "ERROR: /api/search no respondio 200; revisa el mapeo 127.0.0.1:8890 y 'docker compose ps'."
  exit 1
fi

echo "SEARVGA listo en http://127.0.0.1:8890/ (API 200)"
