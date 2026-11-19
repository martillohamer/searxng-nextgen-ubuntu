#!/usr/bin/env bash
set -e

PROYECTO="/mnt/c/Users/astur/Desktop/tubuntu-searxng-nextgen"
cd "$PROYECTO"

echo "=========================================="
echo "   INICIANDO CLÚSTER SEARVGA // T-800     "
echo "=========================================="

docker compose up -d

echo -n "Esperando a que el interfaz (:8890) esté listo"
for i in {1..15}; do
  if curl -s -I http://127.0.0.1:8890 | grep -q "200 OK"; then
    echo " [OK]"
    break
  fi
  echo -n "."
  sleep 1
done

docker ps --filter "name=searvga" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo ""
echo "SearVGA operativo en: http://127.0.0.1:8890"
