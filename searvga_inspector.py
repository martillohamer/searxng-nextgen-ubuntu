"""
searvga_inspector - Microservicio Forense en RAM
FastAPI ultracompacto para inspección de metadatos de archivos/URLs
100% en tmpfs, sin escritura en disco, límite 256M memoria
Usa: pypdf, Pillow, exifread
Todo el tráfico through searvga_tor (socks5h://)
"""

import os
import socket
import ipaddress
import io
import json
import hashlib
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import httpx
import exifread
from PIL import Image
from pypdf import PdfReader
from fastapi import FastAPI, Query, HTTPException, Body
from fastapi.responses import JSONResponse

# Configuración de memoria y límites
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "8"))
MAX_FILE_SIZE = MAX_FILE_SIZE_MB * 1024 * 1024  # Límite seguro en RAM para 256 MiB
MAX_MEMORY_MB = 256
TOR_PROXY = os.getenv("TOR_PROXY", "socks5h://searvga_tor:9150")  # a través de searvga_tor

# Motor LLM local compatible con OpenAI (host, sin pasar por Tor ni por disco)
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://host.docker.internal:3001/v1").rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "auto")
try:
    LLM_TIMEOUT_S = float(os.getenv("LLM_TIMEOUT_S", "35"))
except (TypeError, ValueError):
    LLM_TIMEOUT_S = 35.0

ANALYZE_MODES = ("briefing", "guion", "angulos")
ANALYZE_SYSTEM_PROMPTS = {
    "briefing": (
        "Eres un analista tactico de SEARVGA. Redacta en espanol un briefing operativo "
        "conciso con hallazgos, riesgos y siguiente paso. Responde unicamente con un objeto JSON "
        "con las claves 'text' (string) y 'next_queries' (array de hasta 3 consultas utiles)."
    ),
    "guion": (
        "Eres un guionista de contenidos verticales 9:16. Convierte la informacion en un guion "
        "tactico por escenas con plano, voz en off y duracion aproximada. Responde unicamente con "
        "un objeto JSON con las claves 'text' (string) y 'next_queries' (array de hasta 3 consultas)."
    ),
    "angulos": (
        "Eres un analista de investigacion. Propone angulos de profundizacion, contradicciones "
        "y preguntas abiertas a partir de la evidencia. Responde unicamente con un objeto JSON con "
        "las claves 'text' (string) y 'next_queries' (array de hasta 3 consultas)."
    ),
}

# Rangos y direcciones IP privadas/bloqueadas para la URL de destino
_PRIVATE_NETWORKS = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fd00::/8",
    "fe80::/10",
    "::1/128",
]
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _is_blocked_url(url: str) -> bool:
    """Devuelve True si la URL apunta a una dirección privada/loopback."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return True
        # IPV4
        if ":" not in hostname:
            ip = hostname
            for net in _PRIMARY_IPV4_NETworks if False else []:
                pass
        # Comprobar loopback y privados simples
        if hostname in _LOOPBACK:
            return True
        # IPv4 privados
        if ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("192.168.") or ip.startswith("169.254."):
            return True
        # IPv6 fd/fe80
        if hostname.startswith("fd") or hostname.startswith("fe80"):
            return True
        return False
    except Exception:
        return True


PRIMARY_IPV4_NETworks = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]


# Creación de la app FastAPI
import html
import re


def _extract_html_meta(raw_bytes: bytes) -> Dict[str, Any]:
    """Extrae título y meta descripción básicos de un HTML en memoria."""
    text = raw_bytes[:262144].decode("utf-8", errors="replace")
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
    title = html.unescape(re.sub(r"\s+", " ", title_match.group(1))).strip() if title_match else None

    desc = None
    for m in re.finditer(r"<meta\b([^>]*)>", text, flags=re.IGNORECASE):
        attrs = m.group(1)
        if re.search(r"""\bname\s*=\s*["']?description["']?""", attrs, flags=re.IGNORECASE):
            cm = re.search(r"""\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')""", attrs, flags=re.IGNORECASE)
            if cm:
                val = cm.group(1) if cm.group(1) is not None else cm.group(2)
                desc = html.unescape(re.sub(r"\s+", " ", val)).strip()
                break

    return {
        "titulo": title or None,
        "meta_descripcion": desc or None,
    }


def _detectar_tipo_contenido(url: str, content_type: str, content: bytes) -> str:
    """Detecta tipo de archivo usando Content-Type, firma de bytes y URL."""
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    head = content[:32]
    lower_url = url.lower().split("?", 1)[0]

    if head.startswith(b"%PDF-") or ct == "application/pdf" or lower_url.endswith(".pdf"):
        return "pdf"

    is_img_bytes = (
        head.startswith(b"\xff\xd8\xff")
        or head.startswith(b"\x89PNG\r\n\x1a\n")
        or head.startswith((b"GIF87a", b"GIF89a"))
        or (head.startswith(b"RIFF") and content[8:12] == b"WEBP")
    )
    if ct.startswith("image/") or is_img_bytes or any(
        lower_url.endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".tiff", ".bmp")
    ):
        return "imagen"

    sample_low = content[:4096].decode("utf-8", errors="ignore").lstrip().lower()
    if ct == "text/html" or sample_low.startswith(("<!doctype html", "<html", "<head", "<body")) or "<title" in sample_low[:512]:
        return "html"

    if ct.startswith("text/") or lower_url.endswith((".txt", ".md", ".csv", ".json", ".xml", ".log")):
        return "texto"

    if content and b"\x00" not in content[:4096]:
        sample_txt = content[:2048].decode("utf-8", errors="ignore")
        printable = sum(1 for ch in sample_txt if ch.isprintable() or ch in "\r\n\t")
        if sample_txt and (printable / len(sample_txt)) > 0.95:
            return "texto"

    return "binario"


app = FastAPI(
    title="searvga_inspector",
    description="Microservicio forense de inspección de metadatos en sandbox RAM",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)


async def descargar_con_tor(url: str, max_size: int = MAX_FILE_SIZE) -> tuple[bytes, str]:
    """
    Descarga un archivo exclusivamente a través de la red Tor, leyendo en streaming
    para no cargar todo en memoria y abortando si se supera max_size.
    Usa socks5h:// a través de searvga_tor.
    Lanza excepciones HTTP si excede el tamaño o hay error de red.
    """
    # Validación básica de bloqueo de IPs privadas/loopback
    if _is_blocked_url(url):
        raise HTTPException(status_code=400, detail="URL bloqueada: no se permite acceder a direcciones privadas o loopback a través de Tor")

    limits = httpx.Limits(max_connections=5, max_keepalive_connections=2)
    timeout = httpx.Timeout(connect=10.0, read=15.0, write=15.0, pool=15.0)

    async with httpx.AsyncClient(
        proxy=TOR_PROXY,
        timeout=timeout,
        limits=limits,
        follow_redirects=True,
    ) as client:
        try:
            async with client.stream("GET", url, follow_redirects=True) as response:
                response.raise_for_status()

                cl_header = response.headers.get("content-length")
                if cl_header and cl_header.isdigit() and int(cl_header) > max_size:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Archivo demasiado grande según Content-Length: {int(cl_header)} bytes (máx: {max_size})"
                    )

                # Descarga en streaming con corte inmediato al superar max_size
                content = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=8192):
                    if len(content) + len(chunk) > max_size:
                        raise HTTPException(
                            status_code=413,
                            detail=f"Archivo demasiado grande: supera el límite de {max_size} bytes"
                        )
                    content.extend(chunk)

                ct = response.headers.get("content-type", "")
                return bytes(content), ct
        except HTTPException:
            # Volver a lanzar HTTPException (incluye 400 SSRF y 413 por tamaño)
            raise
        except httpx.HTTPStatusError as e:
            code = e.response.status_code
            if code in (401, 403, 404, 429):
                raise HTTPException(
                    status_code=code,
                    detail=f"Respuesta HTTP {code} del servidor remoto a través de Tor (si es 403/429, prueba ./rotar-ip-tor.sh)"
                )
            raise HTTPException(status_code=502, detail=f"Error HTTP {code} del origen vía Tor: {str(e)}")
        except httpx.HTTPError as e:
            raise HTTPException(status_code=502, detail=f"Error de red/conexión Tor: {str(e)}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error inesperado: {str(e)}")


def extraer_metadata_pdf(content: bytes) -> Dict[str, Any]:
    """Extrae metadatos de un archivo PDF en memoria."""
    metadata = {
        "tipo": "pdf",
        "sha256": hashlib.sha256(content).hexdigest(),
        "autor": None,
        "creador": None,
        "software": None,
        "fecha_creacion": None,
        "fecha_modificacion": None,
        "gps": None,
        "metadatos_adicionales": {}
    }
    
    try:
        reader = PdfReader(io.BytesIO(content))
        
        if reader.metadata:
            meta = reader.metadata
            metadata["autor"] = meta.get("/Author")
            metadata["creador"] = meta.get("/Creator")
            
            # Fecha de creación
            if "/CreationDate" in meta:
                date_str = str(meta["/CreationDate"])
                metadata["fecha_creacion"] = parse_pdf_date(date_str)
            
            if "/ModDate" in meta:
                date_str = str(meta["/ModDate"])
                metadata["fecha_modificacion"] = parse_pdf_date(date_str)
        
        # Extraer información del objeto XMP si está disponible
        # (información adicional del PDF)
        
    except Exception as e:
        metadata["error"] = f"Error extrayendo PDF: {str(e)}"
    
    return metadata


def parse_pdf_date(date_str: str) -> Optional[str]:
    """Parsea una fecha del formato PDF a string legible."""
    if not date_str:
        return None
    try:
        # Formatos comunes: D:20231015120000+02'00' o D:20231015120000Z
        date_str = date_str.strip()
        if date_str.startswith("D:"):
            date_str = date_str[2:]
        # Extract basic date parts
        if len(date_str) >= 15:
            year = date_str[:4]
            month = date_str[4:6]
            day = date_str[6:8]
            hour = date_str[8:10]
            minute = date_str[10:12]
            second = date_str[12:14]
            return f"{year}-{month}-{day}T{hour}:{minute}:{second}Z"
    except:
        pass
    return None


def extraer_metadata_imagen(content: bytes, filename: Optional[str] = None) -> Dict[str, Any]:
    """Extrae metadatos EXIF de una imagen en memoria."""
    metadata = {
        "tipo": "imagen",
        "sha256": hashlib.sha256(content).hexdigest(),
        "formato": None,
        "autor": None,
        "software": None,
        "fecha": None,
        "gps": None,
        "dimensiones": None
    }
    
    try:
        # Determinar formato
        img = Image.open(io.BytesIO(content))
        metadata["formato"] = img.format
        metadata["dimensiones"] = f"{img.width}x{img.height}"
        
        # EXIF data
        exif_data = img._getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag_name = exif_description.get(tag_id, str(tag_id))
                
                if tag_name == "Artist" or tag_name == "Author":
                    metadata["autor"] = str(value)
                elif tag_name == "Software":
                    metadata["software"] = str(value)
                elif tag_name == "DateTimeOriginal":
                    metadata["fecha"] = str(value)
                elif tag_name == "GPSInfo":
                    gps = extract_gps(value)
                    if gps:
                        metadata["gps"] = gps
        
        # Si no hay filename, intentar obtener del content-type o nombre
        if filename:
            metadata["filename"] = filename
            
    except Exception as e:
        metadata["error"] = f"Error extrayendo imagen: {str(e)}"
    
    return metadata


def extract_gps(gps_info: dict) -> Optional[Dict[str, float]]:
    """Extrae coordenadas GPS de la información EXIF."""
    try:
        gps_lat = gps_info.get(2)  # Latitud
        gps_lon = gps_info.get(4)  # Longitud
        
        if gps_lat and gps_lon:
            # Convertir a formato decimal
            lat = convert_to_degrees(gps_lat)
            lon = convert_to_degrees(gps_lon)
            
            # Determinar hemisferio
            lat_ref = gps_info.get(1)  # 'N' o 'S'
            lon_ref = gps_info.get(3)  # 'E' o 'W'
            
            if lat_ref and lat_ref in ('S',):
                lat = -lat
            if lon_ref and lon_ref in ('W',):
                lon = -lon
            
            return {"latitud": round(lat, 6), "longitud": round(lon, 6)}
    except:
        pass
    return None


def convert_to_degrees(value) -> float:
    """Convierte valores EXIF a grados decimales."""
    try:
        if isinstance(value, tuple):
            d, m, s = value
            if isinstance(d, tuple):
                d = d[0] / d[1] if d[1] else 0
            if isinstance(m, tuple):
                m = m[0] / m[1] if m[1] else 0
            if isinstance(s, tuple):
                s = s[0] / s[1] if s[1] else 0
            return float(d) + float(m) / 60.0 + float(s) / 3600.0
        return float(value)
    except:
        return 0.0


# Diccionario de descripción de etiquetas EXIF
exif_description = {
    256: "ImageWidth",
    257: "ImageLength",
    258: "BitsPerSample",
    259: "Compression",
    262: "XResolution",
    263: "YResolution",
    264: "ResolutionUnit",
    270: "Software",
    271: "DateTime",
    272: "Artist",
    273: "Copyright",
    306: "DateTimeOriginal",
    315: "City",
    334: "Country",
    336: "StateOrProvince",
    340: "GPSInfo",
    368: "ImageDescription",
    400: "MakerNote",
    401: "UserComment",
    405: "FlashpixVersion",
    406: "ColorSpace",
    407: "PixelXDimension",
    408: "PixelYDimension",
    409: "RelatedImageFileFormat",
    410: "RelatedImageWidth",
    411: "RelatedImageHeight",
    412: "RelatedImageHeight",
    700: "XMP",
}


@app.get("/inspect")
async def inspect_url(url: str = Query(..., description="URL del archivo a inspeccionar")):
    """
    Endpoint que inspecciona un archivo URL a través de Tor y extrae metadatos.
    
    Parámetros:
    - url: URL del archivo a inspeccionar (descargado through Tor)
    
    Retorna:
    - JSON con metadatos extraídos en memoria
    - Hash SHA-256
    - Tipo de archivo
    """
    try:
        # Validar URL
        if not url or not isinstance(url, str):
            raise HTTPException(status_code=400, detail="URL inválida")
        
        if not (url.startswith("http://") or url.startswith("https://")):
            raise HTTPException(status_code=400, detail="URL debe comenzar con http:// o https://")
        
        # Descargar archivo through Tor
        content, content_type = await descargar_con_tor(url)

        # Calcular hash SHA-256
        sha256_hash = hashlib.sha256(content).hexdigest()
        tipo_detectado = _detectar_tipo_contenido(url, content_type, content)

        # Determinar tipo y extraer metadatos
        metadata = {
            "sha256": sha256_hash,
            "tamanio_bytes": len(content),
            "tipo_archivo": tipo_detectado,
            "content_type": content_type or None,
            "metadatos": {}
        }

        if tipo_detectado == "pdf":
            metadata["metadatos"] = extraer_metadata_pdf(content)
        elif tipo_detectado == "imagen":
            import posixpath
            filename = posixpath.basename(url.lower().split("?")[0])
            metadata["metadatos"] = extraer_metadata_imagen(content, filename=filename if filename else None)
        elif tipo_detectado == "html":
            html_meta = _extract_html_meta(content)
            metadata["metadatos"] = {
                "sha256": sha256_hash,
                "tamanio_bytes": len(content),
                "content_type": content_type or None,
                **html_meta,
            }
        elif tipo_detectado == "texto":
            decoded = content.decode("utf-8", errors="replace") if content else ""
            metadata["metadatos"] = {
                "sha256": sha256_hash,
                "tamanio_bytes": len(content),
                "content_type": content_type or None,
                "contenido_preview": decoded[:500],
                "lineas": decoded.count("\n") + 1 if content else 0,
            }
        else:
            metadata["metadatos"] = {
                "sha256": sha256_hash,
                "tamanio_bytes": len(content),
                "content_type": content_type or None,
                "nota": "Tipo no identificado específicamente, hash calculado correctamente",
            }

        # Asegurar que el hash siempre esté en el resultado principal
        if "sha256" not in metadata["metadatos"]:
            metadata["metadatos"]["sha256"] = sha256_hash
        
        return JSONResponse(content=metadata)
        
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno de inspección: {str(e)}")


def _compact(value, max_chars=300):
    """Recorta texto o serializa valores de forma segura para el prompt."""
    text = " ".join(str(value if value is not None else "").split())
    return text[:max_chars] + ("…" if len(text) > max_chars else "")


def _limit_obj(value, depth=0):
    """Copia acotada en RAM para no enviar payloads enormes al LLM local."""
    if isinstance(value, str):
        return _compact(value)
    if isinstance(value, list):
        return [_limit_obj(v, depth + 1) for v in value[:12]]
    if isinstance(value, dict):
        return {str(k)[:60]: _limit_obj(v, depth + 1) for k, v in list(value.items())[:40]}
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _compact(value)


def _build_analysis_context(query, results, inspect_data, dossier_entries):
    context = {"modo": "analisis", "consulta": _compact(query, 500)}
    if isinstance(results, list) and results:
        context["resultados"] = [_limit_obj(r, 1) for r in results[:12] if r]
    if isinstance(inspect_data, dict) and inspect_data:
        context["inspeccion_rayos_x"] = _limit_obj(inspect_data, 1)
    if isinstance(dossier_entries, list) and dossier_entries:
        context["dossier"] = [_limit_obj(e, 1) for e in dossier_entries[-20:]]
    return context


async def _resolve_llm_model(client):
    """Con LLM_MODEL=auto toma el primer modelo publicado por el servidor local."""
    if LLM_MODEL and LLM_MODEL.lower() != "auto":
        return LLM_MODEL
    try:
        response = await client.get(LLM_BASE_URL + "/models", timeout=min(5.0, LLM_TIMEOUT_S))
        if response.status_code == 200:
            ids = [
                m.get("id") for m in response.json().get("data", [])
                if isinstance(m, dict) and m.get("id")
            ]
            if ids:
                return str(ids[0])
    except Exception:
        pass
    return "local-model"


def _parse_llm_response(content):
    """Acepta JSON con text/next_queries o texto plano; nunca escribe en disco."""
    text = str(content or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    next_queries = []
    if text:
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                raw_text = (
                    obj.get("text") or obj.get("content") or obj.get("analysis")
                    or obj.get("briefing") or ""
                )
                text = _compact(raw_text, 12000) if raw_text else ""
                raw_queries = obj.get("next_queries") or obj.get("suggestions") or []
                if isinstance(raw_queries, str):
                    raw_queries = [raw_queries]
                if isinstance(raw_queries, list):
                    next_queries = [
                        _compact(q, 160) for q in raw_queries
                        if isinstance(q, (str, int, float)) and str(q).strip()
                    ][:3]
        except (ValueError, TypeError):
            pass
    return text, next_queries


@app.post("/analyze")
async def analyze(payload: Dict[str, Any] = Body(...)):
    """
    Célula de inteligencia local: delega en un LLM OpenAI-compatible en el host.
    Solo trabaja en RAM; ningún dato ni respuesta se escribe en disco.
    """
    mode = payload.get("mode") if isinstance(payload, dict) else None
    query = payload.get("query") if isinstance(payload, dict) else None
    if mode not in ANALYZE_MODES:
        return JSONResponse(status_code=400, content={
            "ok": False, "error": "mode debe ser briefing, guion o angulos", "mode": mode
        })
    if not isinstance(query, str) or not query.strip():
        return JSONResponse(status_code=400, content={
            "ok": False, "error": "query es obligatoria y no puede estar vacia", "mode": mode
        })

    context = _build_analysis_context(
        query.strip(),
        payload.get("results"),
        payload.get("inspect_data"),
        payload.get("dossier_entries"),
    )
    messages = [
        {"role": "system", "content": ANALYZE_SYSTEM_PROMPTS[mode]},
        {"role": "user", "content": json.dumps(context, ensure_ascii=False)},
    ]
    try:
        timeout = httpx.Timeout(LLM_TIMEOUT_S, connect=min(5.0, LLM_TIMEOUT_S))
        async with httpx.AsyncClient(timeout=timeout) as client:
            model = await _resolve_llm_model(client)
            response = await client.post(
                LLM_BASE_URL + "/chat/completions",
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": 0.3,
                    "max_tokens": 1400,
                },
            )
            response.raise_for_status()
            llm_data = response.json()
    except httpx.TimeoutException:
        return JSONResponse(status_code=502, content={
            "ok": False, "error": "El motor LLM local no respondio a tiempo", "mode": mode
        })
    except Exception as exc:
        return JSONResponse(status_code=502, content={
            "ok": False,
            "error": "No se pudo contactar con el motor LLM local",
            "detalle": _compact(str(exc), 200),
            "mode": mode,
        })

    try:
        content = llm_data.get("choices", [{}])[0].get("message", {}).get("content", "")
    except (AttributeError, IndexError, TypeError, KeyError):
        content = ""
    text, next_queries = _parse_llm_response(content)
    if not text:
        return JSONResponse(status_code=503, content={
            "ok": False, "error": "El motor LLM local no devolvio contenido valido", "mode": mode
        })

    return JSONResponse(content={
        "ok": True,
        "mode": mode,
        "text": text,
        "next_queries": next_queries,
        "model": model,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.get("/health")
async def health_check():
    """Endpoint de salud para validar que el servicio está running."""
    return JSONResponse(content={
        "status": "healthy",
        "service": "searvga_inspector",
        "memory_limit_mb": MAX_MEMORY_MB,
        "max_file_size_mb": MAX_FILE_SIZE / (1024 * 1024),
        "tor_proxy": TOR_PROXY,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)