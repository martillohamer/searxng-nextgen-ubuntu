#!/usr/bin/env bash
set -euo pipefail

# Punto de entrada unico: siempre usa el proyecto canonico en WSL,
# tanto si se invoca desde /home/danny como desde la copia de Windows.
exec "$HOME/searxng-nextgen-ubuntu/arrancar-searvga.sh" "$@"
