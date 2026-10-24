"""Panel de seguridad de RAM535.

Reune los datos que muestra el panel lateral de la ventana.
No sale a internet. Solo lee archivos del proyecto y hace
dos comprobaciones que no salen del propio equipo.
"""

import json
import socket
import urllib.request
from urllib.parse import urlsplit

import red

# El registro es el mismo archivo que escribe red.py
REGISTRO = red.ARCHIVO_REGISTRO
PUERTO_OLLAMA = 11434

# Hallazgos conocidos. Se escriben a mano, igual que en la hoja de ruta
HALLAZGOS = [
    {
        "id": "H-01",
        "titulo": "El motor WebView2 conecta con substrate.office.com",
        "estado": "Resuelto el 22/10/2026",
        "detalle": "Bloqueado en el archivo hosts de Windows (0.0.0.0 y :: substrate.office.com). "
                   "Comprobado sin conexiones del motor hacia Microsoft. Copia del hosts en hosts.copia-ram535.",
    },
]

# Capas de protección activas, de la ventana hacia fuera
PROTECCIONES = [
    "Ventana sin permisos de red (Content-Security-Policy)",
    "Motor de la ventana con proxy cerrado en 127.0.0.1:9",
    "Diseño cargado con html=, sin servidor ni puertos",
    "Portero de red.py con lista blanca, solo https y puerto 443",
    "DNS comprobado y conexión fija a la IP contra el rebinding",
    "TLS 1.2 como mínimo y certificado verificado",
    "Ritmo de 3 segundos y respeto a robots.txt",
    "Texto descargado limpiado y tratado como datos",
    "Mapa de fuentes validado por el portero",
    "Lista blanca solo interna, nunca se envía a la ventana",
    "Buscador sin cuenta ni clave, como mucho 3 búsquedas por pregunta y cada una con tu aprobación",
    "Altas de una ruta con tu aprobación y del sitio entero con doble confirmación",
    "Como mucho 8 consultas por pregunta, y las de internet con tu aprobación",
    "Bug bounty. Alcance calculado por el programa y nada sale a internet si menciona un programa tuyo",
    "Lecturas antiguas acortadas para no desbordar la memoria del modelo",
    "Segunda capa de hechos. Técnicas fuera de la ficha oficial y consultas inventadas se quitan",
    "Memoria local solo con lo que tú apruebas, consultas SQL con parámetros y borrado seguro",
    "La ventana solo manda números a la memoria, nunca el texto que se guarda (salvo tus notas)",
]


def _ollama_local():
    """Pregunta a Ollama su versión por 127.0.0.1, sin proxy."""
    abridor = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    direccion = f"http://127.0.0.1:{PUERTO_OLLAMA}/api/version"
    try:
        with abridor.open(direccion, timeout=2) as respuesta:
            version = json.loads(respuesta.read(1000)).get("version", "?")
        return {"ok": True, "texto": f"Ollama {version} responde en 127.0.0.1"}
    except Exception:
        return {"ok": False, "texto": "Ollama no responde en 127.0.0.1"}


def _ip_de_red():
    """Averigua la IP del equipo en la red local sin enviar nada.

    Un socket UDP con connect solo consulta la tabla de rutas de Windows.
    192.0.2.1 es una dirección reservada para ejemplos, nunca existe.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            ip = s.getsockname()[0]
    except OSError:
        return None
    return None if ip.startswith("127.") or ip == "0.0.0.0" else ip


def _responde(ip):
    """Intenta abrir una conexión TCP al puerto de Ollama en esa IP."""
    try:
        with socket.create_connection((ip, PUERTO_OLLAMA), timeout=1):
            return True
    except OSError:
        return False


def exposicion():
    """Dos comprobaciones. Ollama vivo en 127.0.0.1 y cerrado hacia la red."""
    local = _ollama_local()
    ip = _ip_de_red()
    if ip is None:
        red = {"ok": True, "texto": "Sin red local, nada que comprobar"}
    elif _responde(ip):
        red = {"ok": False, "texto": f"ALERTA, Ollama responde desde {ip}"}
    else:
        red = {"ok": True, "texto": f"Ollama no responde desde {ip}"}
    return [local, red]


def lista_blanca():
    """La lista blanca tal como la entiende el portero de red.py."""
    try:
        return [sitio + ruta for sitio, ruta in red.cargar_lista()]
    except OSError:
        return []


def _clasificar(entrada):
    """Un robots.txt que no existe (404) es normal, no un error."""
    resultado = entrada.get("resultado")
    codigo = entrada.get("codigo")
    if (resultado == "ERROR" and isinstance(codigo, int) and 400 <= codigo < 500
            and urlsplit(str(entrada.get("url", ""))).path == "/robots.txt"):
        return "SIN_ROBOTS"
    return resultado


class Panel:
    """Recuerda dónde empezaba el registro al abrir RAM535."""

    def __init__(self, desde_el_principio=False):
        if desde_el_principio or not REGISTRO.exists():
            self.inicio = 0
        else:
            self.inicio = REGISTRO.stat().st_size

    def conexiones(self, maximo=30):
        """Conexiones de esta sesión, las más nuevas primero."""
        texto = ""
        if REGISTRO.exists():
            if REGISTRO.stat().st_size < self.inicio:
                self.inicio = 0
            with open(REGISTRO, "rb") as archivo:
                archivo.seek(self.inicio)
                texto = archivo.read().decode("utf-8", "replace")

        entradas = []
        for linea in texto.splitlines():
            try:
                dato = json.loads(linea)
            except ValueError:
                continue
            if isinstance(dato, dict):
                entradas.append(dato)

        contadores = {"OK": 0, "REDIRECCION": 0, "SIN_ROBOTS": 0, "BLOQUEADO": 0, "ERROR": 0, "ALTA": 0}
        for e in entradas:
            tipo = _clasificar(e)
            if tipo in contadores:
                contadores[tipo] += 1

        ultimas = []
        for e in reversed(entradas[-maximo:]):
            ultimas.append({
                "fecha": str(e.get("fecha", "")),
                "resultado": str(_clasificar(e)),
                "url": str(e.get("url", ""))[:300],
                "detalle": str(e.get("detalle", ""))[:200],
            })
        return {"contadores": contadores, "ultimas": ultimas}

    def todo(self):
        """Todo lo que necesita el panel, listo para json.dumps."""
        return {
            "exposicion": exposicion(),
            "conexiones": self.conexiones(),
            "hallazgos": HALLAZGOS,
            "protecciones": PROTECCIONES,
        }


if __name__ == "__main__":
    # Prueba suelta. Lee todo el registro, no solo esta sesión
    print(json.dumps(Panel(desde_el_principio=True).todo(),
                     ensure_ascii=False, indent=2))
