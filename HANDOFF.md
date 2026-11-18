# HANDOFF // SEARVGA T-800

## 📋 Estado del Proyecto
- **Versión:** 1.0.0 (Production Hardened)
- **Entorno:** Ubuntu on WSL2 / Docker Desktop
- **Puerto Local:** `http://127.0.0.1:8890`

## 🔒 Componentes Clave
1. **searvga_core:** Núcleo de búsqueda configurado con `settings.yml` y proxy SOCKS5 hacia el nodo Tor.
2. **searvga_tor:** Contenedor de anonimización en red aislada.
3. **searvga_ui:** Interfaz Nginx limpia y optimizada.

## ⚙️ Comandos de Mantenimiento
- **Iniciar búnker:** `docker compose up -d`
- **Reiniciar núcleo:** `docker compose restart core`
- **Verificar estado:** `docker ps`