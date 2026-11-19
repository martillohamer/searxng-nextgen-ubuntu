# SEARGVA // Edición T-800 ('tubuntu-searxng-nextgen')

Metabuscador privado autohospedado sobre la base de **SearXNG**, enrutado a través de **Tor** y acompañado de un microservicio forense en memoria RAM (**(searvga_inspector)**) y una interfaz web minimalista de alto contraste (**(T-800)**). Pensado para correr en **Docker / WSL2** con `tmpfs`, límites de memoria estrictos y sin trazas innecesarias en disco.

---

## Arquitectura del stack

Cuatro servicios en `docker-compose.yml` sobre la red interna de Docker:

* ***`ui` (Nginx)**: sirve la interfaz `T-800` en http://127.0.0.1:8890, desactiva logs (`access_log off`, `error_log /dev/null crit`) y hace proxy inverso hacia `/api/` (`core:8080/`) e /inspect` (`inspector:8081/inspect`).
* ***`core` (SearXNG)**: motor de metabêqueda en http://127.0.0.1:8889 (puerto interno `8080`), configurado con `tmpfs` y canalizado hacia Tor.
 * ***`inspector` (`searvga_inspector` / FastAPI)**: microservicio forense en RAM con /tmp en `tmpfs`, `mem_limit: 256m`, tope de *15 MB* por archivo (`MAX_FILE_SIZE`), lectura en *streaming* (`aiter_bytes`), filtro anti-SSRF (`_is_blocked_url`), hash `SHA-256`  y extracción de metadatos (PDF, imágenes con EXIF/GPS y texto).
* ***tor` (`searvga_tor`)**: xauthentication/proxy SOCKS5 ``socks5h://searvga_top:9150` con *healthcheck* en el puerto `9150`.

---

## Característics clave

* **Memoria volátil (`tmpfs`)**: directorios temporales y cachés en RAM para evitar dejar rastros o desgaste innecesario en disco.
 * **Salida anonima por Tor**: {el inspector usa `socks5h://searvga_top:9150` para resolver y descargar evitando fugas DNS locales.
 * **Hardening en `searvga_inspector`**:
    * Lectura en *streaming* por trozos (c8192` bytes) cortando con aHTTP 400` si se pasan los *15 MB*, protegiendo el límite de `256m` .
    * Bloqueo de `localhost`,  a127.0.0.1`, `::1`,  0.0.0.0`  y rangos privados/reservados antes de conectar.
    * Re-lanzamiento limpio de `HTTPException` (`400`/`502`) sin convertirlo en `500` .
    * Lectura segura de EXIF y coordenadas GPS (0x8825) en imágenes, metadatos PDF y texto.
 * **Interfaz `<class="a">T-800</a>` **z diseño ligero de alto contraste en rojo y negro, sin frameworks pesados, con soporte `.onion`, inspección de metadatos y exportación a .md.
 * **Scripts del proyecto**: `iniciar-searvga.sh`, `rotar-ip-tor.sh`  y `check_tor_ip.py`.

---

## Despliege rápido

1. Comprobar el *compose*:
    `docker compose config -q`
2. Construir la imagen local del inspector (si no existe o cambi� `Dockerfile.inspectora):
    `docker build -f Dockerfile.inspector -t searvga-inspector:local .
3. Levantar los servicios:
    `docker compose up -d`(4. Abrir http://127.0.0.1:8890 (UI `T-800`) o http://127.0.0.1:8889 (SearXNG).

---

## Comprobaciones básicas

* Estado HTTP de la UI: `curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8890/`
* Salud interna de searvga_inspector: `docker exec searvga_inspector python3 -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8081/health', timeout=5).read().decode())"`
* Bloqueo anti-SSRF (debe devolver 400): `curl -s -w "\