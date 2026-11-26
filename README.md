# SEARVGA // T-800

Buscador local construido sobre SearXNG, con todo el tráfico saliente a través de Tor y un microservicio de inspección forense que trabaja solo en memoria. El stack se ejecuta con Docker Compose y publica sus puertos únicamente en `127.0.0.1`.

## Arquitectura

```text
  Navegador / curl
         |  http://127.0.0.1:8890
         v
  +-------------------------------+
  | searvga_ui (nginx:alpine)     |
  |   /           interfaz T-800  |
  |   /health     JSON estático   |
  |   /api/  -------------+       |
  |   /inspect -----+     |       |
  +-----------------+-----+-------+
                    |     |
        +-----------+     +-----------+
        v                         v
  +----------------+        +----------------+
  | searvga_       |        | searvga_core   |
  | inspector      |        | SearXNG :8080  |
  | :8081 interno  |        | 127.0.0.1:8889 |
  | 256 MiB RAM    |        +--------+-------+
  +--------+-------+                 |
           |                         |
           +------------+------------+
                        v
            searvga_tor:9150 (SOCKS5)
                        v
                     red Tor
```

SearXNG también es accesible directamente en `http://127.0.0.1:8889/`. El resto de los servicios solo se comunican dentro de la red de Docker.

## Servicios

| Servicio (`docker-compose.yml`) | Contenedor | Acceso | Función |
| --- | --- | --- | --- |
| `ui` | `searvga_ui` | `127.0.0.1:8890` | Nginx con la interfaz T-800. Sirve `/health`, invierte `/api/` hacia `core:8080` y `/inspect` hacia `inspector:8081`. |
| `core` | `searvga_core` | `127.0.0.1:8889` | SearXNG: metabúsqueda general y categoría `onions`. Configuración montada desde `./searx`. |
| `inspector` | `searvga_inspector` | solo interno `:8081` | FastAPI: descarga en streaming por Tor, calcula SHA-256 y extrae metadatos de html, texto, pdf, imagen y binario. Límite de 256 MiB de RAM. |
| `tor` | `searvga_tor` | solo interno `:9150` | Proxy SOCKS5 `socks5h://searvga_tor:9150` con healthcheck y `MAX_CIRCUIT_DIRTINESS=180`. |

## Seguridad y límites

- Los cuatro contenedores usan `read_only`, `cap_drop: ALL` y `no-new-privileges`; las rutas temporales son `tmpfs`.
- Solo `8890` y `8889` se publican, y ambas en `127.0.0.1`. El inspector y Tor no exponen puertos al host.
- Nginx añade CSP, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` y `X-Frame-Options: DENY`.
- `/inspect` rechaza con `400` las URL loopback o pertenecientes a rangos IP privados/reservados (protección SSRF).
- Tamaño máximo de descarga: `MAX_FILE_SIZE_MB=8` (8388608 bytes) por defecto. Se comprueba `Content-Length` y se corta el streaming en cuanto se supera el límite, con respuesta `413`.
- Los códigos remotos `401`, `403`, `404` y `429` se propagan; otros fallos HTTP o de red vía Tor se devuelven como `502`.

## Interfaz táctica (`ui/index.html`)

Toda la lógica de la interfaz vive en un único archivo, sin librerías ni CDN. La CSP de Nginx sigue intacta (`script-src 'self' 'unsafe-inline'`, `connect-src 'self'` y el resto de directivas). El grafo es SVG inline creado con `createElementNS` y `addEventListener`; el dossier usa `crypto.subtle`. Web Crypto requiere contexto seguro: funciona en `http://127.0.0.1:8890` (localhost) o por HTTPS.

| Fase | Control | Qué hace |
| --- | --- | --- |
| Fase 1 — Horizonte de Sucesos | `[RAYOS X]` en cada tarjeta y miniatura, panel `RECON` | Inspección bajo demanda vía `/inspect`: estado HTTP, Content-Type, tamaño con tope de 8 MiB, SHA-256 completo con copiar y alertas de EXIF/GPS/autor de PDF o redirecciones sospechosas. Una sola inspección activa para no saturar Tor. Badge `[N MOTORES]` cuando `/api/search` incluye `engines` por resultado. |
| Fase 2 — Grafo Táctico | `GRAFO: OFF/ON` o tecla `G` | Grafo radial en SVG puro: consulta en el centro, dominios agrupados por frecuencia/motores y conceptos repetidos en títulos y snippets; grosor y brillo de aristas según relevancia. Clic en dominio filtra resultados; clic en concepto refina la búsqueda. La etiqueta central se trunca a 18 caracteres con ajuste de ancho y fuente compacta; el panel abierto deja 12 px de margen inferior. |
| Fase 3 — Dossier Zero-Knowledge | `DOSSIER: OCULTO/ABIERTO` o tecla `D` | Captura resultados, inspecciones de Rayos X y notas en RAM. Cifrado con PBKDF2-SHA-256 (120.000 iteraciones) y AES-GCM-256, sal de 16 B e IV de 12 B aleatorios por operación; el texto plano se descarta al bloquear. Desbloqueo, `PURGAR RAM` y exportación local a `.md`/`.json`. Sin localStorage y sin envío de claves al backend. |

Los atajos del HUD son `/` (buscar), `H` (HUD), `G` (grafo), `D` (dossier), `?` (ayuda) y `Esc` (cerrar panel/limpiar). La rotación de Tor se hace en el host con `./rotar-ip-tor.sh`; la UI no expone esa acción.

## Uso paso a paso

1. Requisitos: Docker con Compose y `curl`.

2. Arrancar y validar el stack:

   ```bash
   ./arrancar-searvga.sh
   ```

   El script levanta los cuatro servicios, espera a `/health`, comprueba que `/api/search` con `categories=general` devuelva `200` y muestra `docker compose ps`.

3. Abrir la interfaz en <http://127.0.0.1:8890/>. SearXNG está disponible por separado en <http://127.0.0.1:8889/>.

4. Comprobar los endpoints desde la terminal:

   ```bash
   curl -s http://127.0.0.1:8890/health
   curl -s 'http://127.0.0.1:8890/api/search?q=Java&format=json&categories=general'
   curl -s 'http://127.0.0.1:8890/api/search?q=privacy&format=json&categories=onions'
   ```

5. Inspeccionar una URL a través de Tor:

   ```bash
   curl -s 'http://127.0.0.1:8890/inspect?url=https://example.com'
   ```

6. Rotar el circuito de Tor (NEWNYM; si falla, reinicia el contenedor):

   ```bash
   ./rotar-ip-tor.sh
   ```

7. Estado y consumo: `docker compose ps` y `docker stats --no-stream`. Para detener el stack: `docker compose down`.

## Notas de configuración

- En `searx/settings.yml` la salida por Tor se define con `outgoing.using_tor_proxy: true` y `outgoing.proxies` con `all://: socks5h://searvga_tor:9150`. `request_timeout` es 45 s, `max_request_timeout` 120 s y el motor `ahmia` (categoría `onions`) tiene 60 s; `torch` está marcado como `inactive: true`.
- El límite del inspector se controla con la variable `MAX_FILE_SIZE_MB` en `docker-compose.yml`; el valor por defecto es 8. Cambiarla requiere recrear el contenedor.
- Tras modificar `searvga_inspector.py` es necesario recrear el servicio, porque no se ejecuta con `--reload`: `docker compose up -d --force-recreate inspector`.
- Los respaldos locales en `.searvga-backups/` están excluidos en `.gitignore` y no forman parte del repositorio.
