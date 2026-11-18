# SEARVGA // T-800 MATRIX EDITION

> Motor de búsqueda privado, anónimo y en memoria RAM, optimizado para entornos de investigación segura y zero-trace.

## 🛠️ Arquitectura y Blindaje
- **Modo RAM-Only (tmpfs):** Los datos y cachés operan exclusivamente en memoria volátil. Al apagar el equipo o reiniciar, no queda rastro físico.
- **Anonimato Tor:** Enrutamiento obligatorio de todas las peticiones salientes a través de un proxy SOCKS5 integrado.
- **Cero Registros (Zero-Logs):** Desactivación absoluta de trazas de consola y logs en disco.
- **Interfaz T-800:** Diseño minimalista y limpio inspirado en estéticas cinematográficas de ciencia ficción.

## 🚀 Despliegue Rápido
```bash
docker compose up -d
```

--- *Desarrollado y adaptado por martillohamer (Estudiante de DAW) sobre la arquitectura base de SearXNG.*