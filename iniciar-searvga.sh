#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "[1/4] Verificando motor Docker en WSL..."
if ! docker info >/dev/null 2>&1; then
    echo "      -> Arrancando servicio Docker..."
    sudo service docker start >/dev/null 2>&1 || true
    sleep 3
fi

echo "[2/4] Levantando bunker SearVGA (UI + Core + Tor RAM)..."
docker compose up -d

echo "[3/4] Esperando circuito Tor (healthy)..."
for i in {1..30}; do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' searvga_tor 2>/dev/null || echo "starting")
    if [ "$STATUS" = "healthy" ]; then
        echo "      -> Tunel Tor ACTIVO y saludable ($i s)."
        break
    fi
    sleep 1
done

echo "[4/4] Verificando interfaz en http://127.0.0.1:8890 ..."
for i in {1..15}; do
    if curl -s -o /dev/null http://127.0.0.1:8890; then
        echo "      -> Interfaz T-800 ONLINE."
        exit 0
    fi
    sleep 1
done

echo "[!] Aviso: El servicio tardo mas de lo esperado, revisa docker ps."
exit 1
