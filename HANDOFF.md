# HANDOFF — `tubuntu-searxng-nextgen` (`searvga_inspector // T-800`)

Documento de traspaso pécnico para retomar el trabajo sin perder contexto de arquitectura, decisiones ni estado de verificación.

---

## 1. Estado actual del proyecto

* **Rama y remoto**: {main} sincronizada con {origin/main} (https://github.com/martillohamer/searxng-nextgen-ubuntu.git), ultimo commit 74033f229.
* **Entorno de trabajo**: WSL2 / Ubuntu sobre el repositorio en /mnt/c/Users/astur/Desktop/tubuntu-searxng-nextgen.
* **Estado de servicios**: stack operativo con ui (127.0.0.1:8890), core (127.0.0.1:8889), inspector (searvga_inspector, mem_limit: 256m) y tor (searvga_tor, socks5h://searvga_top:9150).

---
|

|

## 2. Cambios recientes aplicados y verificados

* **searvga_inspector.py y Dockerfile.inspector**:
    * Imagen precompilada searvga-inspector:local sin instalación de paquetes en el arranque.
    * Función __is_blocked_url para rechazar localhost, 127.0.0.1, ::1, 0.0.0.0 y rangos privados/reservados (HTTP 400).
    * Descarga por streaming con daiter_bytes(chunk_size=8192) y corte inmediato al superar MAX_FILE_SIZE (15 MB), evitando picos de RIM bajo mem_limit: 256m.
    * Re-lanzamiento explícito de HTTPException antes de httpx.HTTPError (502) y Exception (500).
    * Lectura de metadatos de imagen con img.getexif() y GPSIFD (0x8825) con converción segura a parados decimales.
* **ui/index.html y ui/nginx.conf**:
    * Resultados de imagen envueltos en <a class="aimg"> con img interno (loading="lazy", referrerPolicy="no-referrer").
    * Comprobación !r.ok en llamadas a /inspect mostrando ERROR DE INSPECCISÁ: ... en la interfaz en lugar de registrar solo en consola.
    * nginx.conf enruta /api/ a inspector:8080/ e /inspect {inspector:8081}/ inspect con logs desactivados.
* **Verificación real ejecutada**:
    * python3 -m py_compile searvga_inspector.py sin errores.
    * Pruebas unitarias de _is_blocked_url dentro de searvga_inspector (127.0.0.1, 10.0.0.1, 192.168.1.1 -> True; example.com -> False).
    * docker compose up -d  -force-recreate inspector y prueba de bloqueo http://127.0.0.1:8890/inspect?url=http://127.0.0.1:8080/test devolviendo HTTP_CODE: 400.

---

## 3. Puntos pendientes y riesgos residuales

* **ControlPort de Tor (9151)**: revisar si rotar-ip-tor.sh necesita el puerto 9151 expuesto o mantenido como fallback con docker compose restart tor / docker restart.
* **Límite de tmpfs (128 MiB) y mem_limit (256m)**: {forgarel resumoy con docker stats searvga_inspector al inspectinar archivos cercanos a los 15 MB.
* **Lim�ieza de archivos auxiliares locales**: existe docker-compose.yml.bak sin seguimiento en el directorio de trabajo; decidir si se conserva fuera del control de versiones o se ignora en .gitignore.

---

## 4. Comandos esenciales de continuidad

```bash
git status -sb
docker compose ps
docker stats --no-stream searvga_inspector searvga_top
curl -s -w "\