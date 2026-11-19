# SEARVGA // T-800

Buscador privado sobre SearXNG, Tor y Nginx con searvga_inspector.

## Servicios (4 contenedores)
- searvga_ui (127.0.0.1:8890): interfaz T-800, Nginx y /health
- searxng / searvga_core (127.0.0.1:8889): motor de busqueda
- searvga_inspector (interno :8081, 256 MiB RAM): analisis por Tor en streaming y metadatos
- searvga_tor (healthy): proxy SOCKS5 socks5h://searvga_tor:9150

## Seguridad y limites
- read_only, cap_drop: ALL, no-new-privileges y tmpfs en rutas temporales
- Bloqueo SSRF (400) para IPs locales/privadas/reservadas
- Limite por defecto MAX_FILE_SIZE_MB=8 (8388608 bytes) con corte en streaming y 413

## Uso paso a paso
1. Arrancar: ./iniciar-searvga.sh (levanta stack y espera :8890/health)
2. Probar /inspect: curl -s "http://127.0.0.1:8890/inspect?url=https://example.com"
3. Rotar IP Tor: ./rotar-ip-tor.sh
4. Ver estado/RAM: docker compose ps && docker stats --no-stream
