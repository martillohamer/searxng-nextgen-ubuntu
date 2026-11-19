# HANDOFF — SEARVGA // T-800

Estado: Operativo y verificado (commit c2e1bbc6c en main).

## Cambios clave y por que
- Seguridad en docker-compose.yml: read_only, cap_drop: ALL, no-new-privileges y tmpfs en rutas temporales para reducir superficie de ataque y evitar escrituras en disco.
- Limite de 8 MB en streaming (searvga_inspector.py): MAX_FILE_SIZE_MB=8 (8388608 bytes) frente al tope de 256 MiB del contenedor; revisa Content-Length y corta el flujo devolviendo 413 si supera el limite.
- Deteccion y metadatos: clasifica html, texto, pdf, imagen y binario con sha256, titulo/descripcion HTML y metadatos de PDF/imagen.
- Arranque y salud: iniciar-searvga.sh levanta el stack, comprueba http://127.0.0.1:8890/health hasta 15s y sale con error si no responde.

## Notas practicas
- Al cambiar searvga_inspector.py (sin --reload), recrea el servicio: docker compose up -d --force-recreate inspector.
- Si un sitio remoto devuelve 403/429 por Tor, el inspector responde 502; puedes probar con ./rotar-ip-tor.sh.
- Queda docker-compose.yml.bak sin rastrear en el directorio de trabajo.
