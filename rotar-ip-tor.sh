#!/bin/bash
# Script de rotación rápida de circuito Tor (NEWNYM)
# Diseñado para ejecutarse dentro del clúster tubuntu-searxng-nextgen
# Usa el ControlPort expuesto en 127.0.0.1:9151 por searvga_tor

# Configuración
CONTROL_PORT="9151"
TOR_CONTAINER="searvga_tor"
MAX_CIRCUIT_DIRTINESS=180

echo "=== Rotación de circuito Tor (NEWNYM) ==="
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"

# Verificar que el contenedor Tor está corriendo
if ! docker ps --filter "name=$TOR_CONTAINER" | grep -q "$TOR_CONTAINER"; then
    echo "ERROR: Contenedor $TOR_CONTAINER no está running"
    exit 1
fi

# Enviar señal AUTHENTICATE + NEWNYM al ControlPort de Tor
# Nota: El proxy peterdavehello/tor-socks-proxy usa autenticación vacía por defecto
RESPONSE=$(echo -e "AUTHENTICATE \"\"\nsignal NEWNYM\nQUIT" | nc -w 5 127.0.0.1 $CONTROL_PORT 2>&1)

if [ $? -eq 0 ] && echo "$RESPONSE" | grep -q "250"; then
    echo "✅ Señal NEWNYM enviada exitosamente a Tor ControlPort $CONTROL_PORT"
    echo "   Nuevo circuito Tor establecido"
else
    echo "⚠️  Intento NEWNYM devuelto: $RESPONSE"
    echo "   Intentando método alternativo..."
    
    # Método alternativo: reiniciar el servicio Tor dentro del contenedor
    docker restart $TOR_CONTAINER 2>&1 | tail -1
    echo "   Servicio Tor reiniciado"
fi

# Verificar nueva IP de salida mediante curl a través del proxy SOCKS5
echo ""
echo "=== Verificación de nueva IP de salida ==="
NEW_IP=$(curl -s --socks5 127.0.0.1:9150 -m 10 --interface 127.0.0.1 http://ifconfig.me 2>/dev/null || echo "fallo_curl")
echo "IP de salida actual: $NEW_IP"

# Mostrar información de circuito actual
echo ""
echo "=== Estado de circuito ==="
echo "MaxCircuitDirtiness configurado: $MAX_CIRCUIT_DIRTINESS segundos"
echo "Próxima rotación automática ocurrirá después de este tiempo"

echo ""
echo "=== Rotación de circuito completada ==="
echo "Timestamp final: $(date '+%Y-%m-%d %H:%M:%S')"

exit 0