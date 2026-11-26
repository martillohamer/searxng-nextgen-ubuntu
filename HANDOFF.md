# HANDOFF — SEARVGA // T-800

Estado: operativo en `main` (HEAD `7e5450367`). Punto de respaldo: tag `Ubuntor-Final`.

## Arquitectura real

Cuatro servicios en `docker-compose.yml`:

- `ui` / `searvga_ui`: Nginx en `127.0.0.1:8890`. Sirve la interfaz T-800, responde `/health` de forma estática, envía `/api/` a `core:8080` y `/inspect` a `inspector:8081` (con `proxy_read_timeout 20s`).
- `core` / `searvga_core`: SearXNG en `127.0.0.1:8889`, con `./searx` montado en `/etc/searxng`.
- `inspector` / `searvga_inspector`: FastAPI construida desde `Dockerfile.inspector`, escucha `:8081` solo en la red interna y tiene `mem_limit: 256m`.
- `tor` / `searvga_tor`: SOCKS5 `socks5h://searvga_tor:9150` con healthcheck `nc -z`, `MAX_CIRCUIT_DIRTINESS=180` y sin exponer el puerto al host.

## Decisiones clave y por qué

- **Salida por Tor para todo SearXNG**: `outgoing.using_tor_proxy: true` junto con `outgoing.proxies.all:// = socks5h://searvga_tor:9150`. La forma anterior (`proxy` como lista) hacía que `check_network_configuration()` fallara con `ProxyError: not using Tor`.
- **Timeouts y estabilidad de `onions`**: `request_timeout: 45`, `max_request_timeout: 120`, `ahmia` con 60 s y `torch` con `inactive: true`. Así la latencia de Tor no genera falsos timeouts y la categoría `onions` responde de forma consistente con resultados de `ahmia`.
- **Endurecimiento de contenedores**: `read_only`, `cap_drop: ALL`, `no-new-privileges` y `tmpfs` en las rutas temporales de los cuatro servicios para reducir superficie de escritura y de privilegios.
- **Inspector en RAM y con límites**: `MAX_FILE_SIZE_MB=8` (8388608 bytes) con comprobación de `Content-Length` y corte en streaming que devuelve `413`; validación SSRF que bloquea loopback y rangos privados/reservados con `400`; `401`/`403`/`404`/`429` remotos se propagan y el resto de fallos se traducen a `502`. Detecta html, texto, pdf, imagen y binario, calcula SHA-256 y extrae título/descripción HTML y metadatos de PDF/imagen (incluido GPS cuando está presente).
- **Arranque único**: `./arrancar-searvga.sh` es el script principal; levanta el stack, espera `/health` y valida `/api/search?...categories=general` con `200` antes de dar por bueno el arranque. El antiguo envoltorio `iniciar-searvga.sh` ya no existe.
- **Incidente resuelto (502 desde el host)**: un contenedor nginx huérfano retenía el enlace de `127.0.0.1:8890` y redirigía a una IP antigua; se eliminaron el huérfano y su `docker-proxy`, y se recreó el stack. Los respaldos locales correspondientes están en `.searvga-backups/`, ignorado por Git.

## Estado de la interfaz (Fases 1 a 3)

- `81321185c` — Fase 1, Horizonte de Sucesos: botón `[RAYOS X]` en tarjetas y miniaturas, panel `RECON` con estado HTTP de `/inspect`, Content-Type, tamaño/tope de 8 MiB, SHA-256 con copiar y alertas de metadatos y redirecciones; badge `[N MOTORES]` a partir de `engines`. Una sola inspección activa para no saturar Tor.
- `cd6b20290` — Fase 2, Grafo Táctico: alternable con `GRAFO: OFF/ON` o tecla `G`. SVG puro (`createElementNS` + `addEventListener`), nodo central con la consulta, dominios por frecuencia/motores y conceptos de títulos/snippets; aristas con grosor/brillo proporcional. Clic en dominio filtra resultados; clic en concepto refina la búsqueda.
- `bf7a1ecb9` — Fase 3, Dossier Zero-Knowledge: panel `DOSSIER // RAM (AES-GCM)` con tecla `D`. Captura de resultados, Rayos X y notas; PBKDF2-SHA-256 (120.000 iteraciones) + AES-GCM-256 con sal de 16 B e IV de 12 B aleatorios por operación; el plaintext se descarta al bloquear. Desbloqueo, `PURGAR RAM` y exportación local a `.md`/`.json`. Clave solo en memoria de la sesión: ni `localStorage` ni peticiones con secretos.
- `7e5450367` — Pulido del grafo: etiqueta central truncada a 18 caracteres con `…` y ajuste mediante `textLength`/fuente compacta; `margin-bottom: 12px` en `.grafo.on`.

No se añadieron dependencias: `ui/index.html` es autocontenido y `ui/nginx.conf` conserva la CSP original (`default-src 'self'`, `connect-src 'self'`, etc.). Web Crypto exige contexto seguro; en local se usa `http://127.0.0.1:8890`.

Arranque y operación: `./arrancar-searvga.sh` levanta el stack y valida `/health` y `/api/search`; la rotación del circuito de Tor se ejecuta en el host con `./rotar-ip-tor.sh` y no se expone desde la UI.

## Notas prácticas

- Si se modifica `searvga_inspector.py`, recrear el servicio porque no corre con `--reload`: `docker compose up -d --force-recreate inspector`.
- Si un sitio remoto responde `403`/`429` (o el inspector devuelve `502`) al acceder por Tor, rotar el circuito con `./rotar-ip-tor.sh`.
- Comprobaciones rápidas: `curl -s http://127.0.0.1:8890/health`, `docker compose ps` y `docker stats --no-stream`.
- Un cambio en `searx/settings.yml` requiere recrear `core`; un cambio en `ui/nginx.conf` o `ui/index.html`, recrear `ui`.
