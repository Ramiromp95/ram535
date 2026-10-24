"""
red.py
Único archivo de RAM535 autorizado a salir a internet.

Paso 4.3. Leer la lista blanca y decidir si una dirección está permitida.
Paso 4.4. Descargar una dirección permitida con todas las protecciones.
Paso 4.5. Ir a un ritmo tranquilo y respetar el robots.txt de cada sitio.
Paso 4.6. Anotar cada intento de conexión en registro/conexiones.jsonl.
Paso 4.9. Avisar al panel de seguridad tras cada anotación.
Paso 4.9f. Añadir a la lista blanca lo que el usuario apruebe desde la ventana.
Paso 4.10. Una ruta sin barra final ya no permite rutas que solo empiezan igual (H-02).
Ajuste 7.3. enviar_json para el buscador. Mismo portero, DNS, IP fija, TLS, ritmo y registro.
"""

import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
from datetime import date, datetime
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit
from urllib.robotparser import RobotFileParser

CARPETA = Path(__file__).resolve().parent
ARCHIVO_LISTA = CARPETA / "lista_blanca.txt"
CARPETA_REGISTRO = CARPETA / "registro"
ARCHIVO_REGISTRO = CARPETA_REGISTRO / "conexiones.jsonl"

LIMITE_BYTES = 2 * 1024 * 1024
TIEMPO_MAXIMO = 15
MAX_REDIRECCIONES = 5
ESPERA_MINIMA = 3
# Fase 8. NVD sin clave solo admite 5 peticiones cada 30 segundos. Con 6 segundos nunca se pasa.
ESPERAS = {"services.nvd.nist.gov": 6}
REDIRECCIONES = (301, 302, 303, 307, 308)
AGENTE = "RAM535/0.4 (uso educativo personal)"

CONTEXTO = ssl.create_default_context()
CONTEXTO.minimum_version = ssl.TLSVersion.TLSv1_2


class ErrorRed(Exception):
    """La descarga no se pudo completar. Guarda el código del sitio si lo hubo."""

    def __init__(self, mensaje, codigo=None):
        super().__init__(mensaje)
        self.codigo = codigo


class Bloqueado(ErrorRed):
    """La descarga se detuvo por una regla de seguridad."""


def cargar_lista():
    """Lee lista_blanca.txt y devuelve pares (sitio, ruta)."""
    entradas = []
    texto = ARCHIVO_LISTA.read_text(encoding="utf-8-sig")
    for linea in texto.splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#"):
            continue
        sitio, barra, ruta = linea.partition("/")
        entradas.append((sitio.lower(), barra + ruta))
    return entradas


def _ruta_dentro(ruta, ruta_ok):
    """La ruta está dentro de la zona permitida.

    Con barra final (/doc/) vale todo lo que empiece así. Sin barra final
    (/hacktivity) vale esa página y lo que cuelga de ella (/hacktivity/...),
    pero no /hacktivityfalsa.
    """
    if not ruta_ok or ruta_ok.endswith("/"):
        return ruta.startswith(ruta_ok)
    return ruta == ruta_ok or ruta.startswith(ruta_ok + "/")


def comprobar(url, entradas):
    """Decide si una dirección se puede visitar. Devuelve (permitida, motivo)."""
    try:
        partes = urlsplit(url)
        sitio = (partes.hostname or "").lower()
        puerto = partes.port
    except ValueError:
        return False, "dirección mal formada"

    if partes.scheme != "https":
        return False, "solo se permite https"

    if partes.username or partes.password:
        return False, "la dirección lleva usuario o contraseña"

    if not sitio:
        return False, "falta el nombre del sitio"

    if puerto not in (None, 443):
        return False, "solo se permite el puerto 443"

    try:
        ipaddress.ip_address(sitio)
        return False, "solo se permiten nombres, no direcciones IP"
    except ValueError:
        pass

    ruta = unquote(partes.path) or "/"
    if "\\" in ruta or ".." in ruta.split("/"):
        return False, "la ruta intenta salirse de la zona permitida"

    if ruta == "/robots.txt" and any(sitio == s for s, _ in entradas):
        return True, "permitida, archivo robots.txt"

    for sitio_ok, ruta_ok in entradas:
        if sitio == sitio_ok and _ruta_dentro(ruta, ruta_ok):
            return True, "permitida"

    return False, f"{sitio} con esa ruta no está en la lista blanca"


# ---------- Altas en la lista blanca ----------

SECCION_ALTAS = "# Añadidos desde la ventana de RAM535"
_SITIO_VALIDO = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+")
_RUTA_VALIDA = re.compile(r"(/[A-Za-z0-9._~%!$&'()*+,;=:@-]*)*/")
_candado_lista = threading.Lock()


def _nombre_valido(sitio):
    """Un nombre de sitio normal. Nunca una IP ni un nombre con letras de otros alfabetos."""
    if not _SITIO_VALIDO.fullmatch(sitio) or "xn--" in sitio:
        return False
    try:
        ipaddress.ip_address(sitio)
        return False
    except ValueError:
        pass
    # El final (com, org, es...) tiene que llevar letras. Así 10.0.0.1 tampoco cuela.
    return not sitio.rsplit(".", 1)[-1].isdigit()


def se_puede_anadir(url, motivo):
    """Solo se ofrece añadir lo bloqueado por no estar en la lista. Lo bloqueado por
    otra regla (http, IP, contraseña, puerto, ..) nunca se puede añadir."""
    if not motivo.endswith("no está en la lista blanca"):
        return False
    # xn-- son nombres con letras de otros alfabetos, con riesgo de suplantación.
    return _nombre_valido((urlsplit(url).hostname or "").lower())


def propuesta_alta(url):
    """Las dos líneas que se podrían escribir. La ruta es la carpeta de la dirección."""
    partes = urlsplit(url)
    sitio = partes.hostname.lower()
    ruta = unquote(partes.path or "/")
    ruta = ruta[: ruta.rfind("/") + 1] or "/"
    return {
        "sitio": sitio,
        "linea_ruta": sitio + ruta if ruta != "/" else None,
        "linea_sitio": sitio,
    }


def anadir_a_lista(linea):
    """Añade una línea al final de lista_blanca.txt, con la fecha en una nota encima."""
    sitio, barra, ruta = linea.partition("/")
    if not _nombre_valido(sitio):
        raise ValueError("nombre de sitio no válido")
    if barra and (not _RUTA_VALIDA.fullmatch("/" + ruta) or ".." in ruta.split("/")):
        raise ValueError("ruta no válida")

    with _candado_lista:
        texto = ARCHIVO_LISTA.read_text(encoding="utf-8-sig")
        if linea in (l.strip() for l in texto.splitlines()):
            return False
        if not texto.endswith("\n"):
            texto += "\n"
        if SECCION_ALTAS not in texto:
            texto += f"\n{SECCION_ALTAS}\n"
        texto += f"# {date.today().strftime('%d/%m/%Y')}\n{linea}\n"
        ARCHIVO_LISTA.write_text(texto, encoding="utf-8")
    registrar(f"https://{linea}", "ALTA", "añadido a la lista blanca desde la ventana")
    return True


def resolver(sitio):
    """Pregunta al DNS la IP del sitio y la rechaza si no es pública."""
    try:
        respuestas = socket.getaddrinfo(sitio, 443, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        raise ErrorRed(f"no se encuentra el sitio {sitio}")

    ips = [r[4][0] for r in respuestas]
    for ip in ips:
        if not ipaddress.ip_address(ip).is_global:
            raise Bloqueado(f"{sitio} apunta a una dirección no pública {ip}")
    return ips[0]


class ConexionFija(http.client.HTTPSConnection):
    """Conexión HTTPS a la IP ya comprobada, verificando el certificado del sitio."""

    def __init__(self, sitio, ip):
        super().__init__(sitio, 443, timeout=TIEMPO_MAXIMO, context=CONTEXTO)
        self.ip = ip

    def connect(self):
        sock = socket.create_connection((self.ip, 443), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


_ultima_visita = {}


def esperar_turno(sitio):
    """Deja al menos ESPERA_MINIMA segundos entre dos peticiones al mismo sitio."""
    anterior = _ultima_visita.get(sitio)
    if anterior is not None:
        falta = ESPERAS.get(sitio, ESPERA_MINIMA) - (time.monotonic() - anterior)
        if falta > 0:
            time.sleep(falta)
    _ultima_visita[sitio] = time.monotonic()


_robots = {}


def permitido_por_robots(url, entradas):
    """Lee el robots.txt del sitio una vez por sesión y respeta lo que diga."""
    sitio = urlsplit(url).hostname.lower()
    if sitio not in _robots:
        lector = RobotFileParser()
        try:
            _, texto = descargar(f"https://{sitio}/robots.txt", entradas, revisar_robots=False)
            lector.parse(texto.splitlines())
        except ErrorRed as error:
            if error.codigo is not None and 400 <= error.codigo < 500:
                lector.allow_all = True
            else:
                raise ErrorRed(f"no se pudo leer el robots.txt de {sitio}")
        _robots[sitio] = lector
    return _robots[sitio].can_fetch(AGENTE, url)


_candado_registro = threading.Lock()

# main.py pone aquí una función para avisar al panel. Sin ventana se queda en None.
al_registrar = None


def registrar(url, resultado, detalle, codigo=None, ip=None, tamano=None, segundos=None):
    """Añade una línea al registro de conexiones. El programa nunca borra nada."""
    entrada = {
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "resultado": resultado,
        "url": url,
        "ip": ip,
        "codigo": codigo,
        "bytes": tamano,
        "segundos": segundos,
        "detalle": detalle,
    }
    with _candado_registro:
        CARPETA_REGISTRO.mkdir(exist_ok=True)
        with ARCHIVO_REGISTRO.open("a", encoding="utf-8") as archivo:
            archivo.write(json.dumps(entrada, ensure_ascii=False) + "\n")

    # El aviso va fuera del candado. Si el panel falla, la descarga sigue igual.
    if al_registrar is not None:
        try:
            al_registrar()
        except Exception:
            pass


def _salto(url, entradas, revisar_robots):
    """Hace una sola petición y devuelve un resumen de lo que respondió el sitio."""
    permitida, motivo = comprobar(url, entradas)
    if not permitida:
        raise Bloqueado(motivo)

    if revisar_robots and not permitido_por_robots(url, entradas):
        raise Bloqueado("el robots.txt del sitio no permite leer esta página")

    partes = urlsplit(url)
    ip = resolver(partes.hostname)
    esperar_turno(partes.hostname)
    ruta = partes.path or "/"
    if partes.query:
        ruta += "?" + partes.query

    conexion = ConexionFija(partes.hostname, ip)
    try:
        conexion.request("GET", ruta, headers={
            "User-Agent": AGENTE,
            "Accept-Encoding": "identity",
        })
        respuesta = conexion.getresponse()

        if respuesta.status in REDIRECCIONES:
            destino = urljoin(url, respuesta.getheader("Location", ""))
            return {"codigo": respuesta.status, "ip": ip, "destino": destino}

        if respuesta.status != 200:
            raise ErrorRed(
                f"el sitio respondió con el código {respuesta.status}",
                respuesta.status,
            )

        datos = respuesta.read(LIMITE_BYTES + 1)
        if len(datos) > LIMITE_BYTES:
            raise Bloqueado("la página supera el límite de 2 MB")

        juego = respuesta.headers.get_content_charset()
        return {"codigo": 200, "ip": ip, "datos": datos, "juego": juego}

    except (OSError, http.client.HTTPException) as error:
        raise ErrorRed(f"fallo de conexión ({type(error).__name__})")
    finally:
        conexion.close()


def enviar_json(url, cuerpo, entradas, cabeceras=None, detalle="consulta a una API"):
    """Ajuste 7.3. Envía un JSON por POST a una API de la lista blanca y devuelve el JSON de
    respuesta. Sin redirecciones ni robots.txt, porque es una API documentada para programas
    y no una página. Todo lo demás es igual que en descargar."""
    permitida, motivo = comprobar(url, entradas)
    if not permitida:
        registrar(url, "BLOQUEADO", motivo)
        raise Bloqueado(motivo)
    partes = urlsplit(url)
    datos = json.dumps(cuerpo).encode("utf-8")
    inicio = time.monotonic()
    try:
        ip = resolver(partes.hostname)
    except ErrorRed as error:
        registrar(url, "BLOQUEADO" if isinstance(error, Bloqueado) else "ERROR", str(error))
        raise
    esperar_turno(partes.hostname)
    conexion = ConexionFija(partes.hostname, ip)
    try:
        conexion.request("POST", partes.path or "/", body=datos, headers={
            "User-Agent": AGENTE,
            "Accept-Encoding": "identity",
            "Content-Type": "application/json",
            **(cabeceras or {}),
        })
        respuesta = conexion.getresponse()
        recibido = respuesta.read(LIMITE_BYTES + 1)
    except (OSError, http.client.HTTPException) as error:
        registrar(url, "ERROR", f"fallo de conexión ({type(error).__name__})", ip=ip)
        raise ErrorRed(f"fallo de conexión ({type(error).__name__})")
    finally:
        conexion.close()
    segundos = round(time.monotonic() - inicio, 2)
    if respuesta.status != 200:
        registrar(url, "ERROR", detalle, codigo=respuesta.status, ip=ip, segundos=segundos)
        raise ErrorRed(f"el sitio respondió con el código {respuesta.status}", respuesta.status)
    if len(recibido) > LIMITE_BYTES:
        registrar(url, "BLOQUEADO", "la respuesta supera el límite de 2 MB", ip=ip)
        raise Bloqueado("la respuesta supera el límite de 2 MB")
    registrar(url, "OK", detalle, codigo=200, ip=ip, tamano=len(recibido), segundos=segundos)
    try:
        return json.loads(recibido.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        raise ErrorRed("la respuesta no es un JSON válido")


def descargar(url, entradas, revisar_robots=True):
    """Descarga una dirección permitida. Devuelve (dirección final, texto)."""
    for _ in range(MAX_REDIRECCIONES + 1):
        inicio = time.monotonic()
        try:
            salto = _salto(url, entradas, revisar_robots)
        except ErrorRed as error:
            resultado = "BLOQUEADO" if isinstance(error, Bloqueado) else "ERROR"
            registrar(url, resultado, str(error), codigo=error.codigo)
            raise
        segundos = round(time.monotonic() - inicio, 2)

        if "destino" in salto:
            registrar(url, "REDIRECCION", f"hacia {salto['destino']}",
                      codigo=salto["codigo"], ip=salto["ip"], segundos=segundos)
            url = salto["destino"]
            continue

        datos = salto["datos"]
        registrar(url, "OK", "descargada", codigo=200, ip=salto["ip"],
                  tamano=len(datos), segundos=segundos)
        try:
            texto = datos.decode(salto["juego"] or "utf-8", errors="replace")
        except LookupError:
            texto = datos.decode("utf-8", errors="replace")
        return url, texto

    registrar(url, "BLOQUEADO", "demasiadas redirecciones")
    raise Bloqueado("demasiadas redirecciones")


if __name__ == "__main__":
    lista = cargar_lista()
    print(f"Entradas cargadas {len(lista)}")
    print()

    print("Pruebas del portero")
    pruebas = [
        ("https://attack.mitre.org/techniques/T1059/", True),
        ("https://learn.microsoft.com/es-es/credentials/certifications/", True),
        ("https://attack.mitre.org/robots.txt", True),
        ("https://learn.microsoft.com/robots.txt", True),
        ("https://learn.microsoft.com/es-es/windows/", False),
        ("http://attack.mitre.org/", False),
        ("https://ejemplo-malo.com/", False),
        ("https://ejemplo-malo.com/robots.txt", False),
        ("https://attack.mitre.org.ejemplo-malo.com/", False),
        ("https://127.0.0.1/", False),
        ("https://learn.microsoft.com/es-es/credentials/../windows/", False),
        ("https://usuario:clave@attack.mitre.org/", False),
        ("https://attack.mitre.org:8443/", False),
    ]
    aciertos = 0
    for url, esperado in pruebas:
        permitida, motivo = comprobar(url, lista)
        if permitida == esperado:
            aciertos += 1
        else:
            print(f"FALLO  {url}")
            print(f"    {motivo}")
    print(f"{aciertos} de {len(pruebas)} correctas")

    print()
    print("Pruebas de descarga")
    descargas = [
        "https://owasp.org/www-project-top-ten/",
        "https://attack.mitre.org/techniques/T1059/",
        "https://ejemplo-malo.com/",
    ]
    for url in descargas:
        inicio = time.monotonic()
        try:
            final, texto = descargar(url, lista)
            print(f"OK  {final}")
            print(f"    {len(texto)} caracteres en {time.monotonic() - inicio:.1f} s")
        except Bloqueado as error:
            print(f"BLOQUEADO  {url}")
            print(f"    {error}")
        except ErrorRed as error:
            print(f"ERROR  {url}")
            print(f"    {error}")

    print()
    print("Últimas líneas del registro")
    lineas = ARCHIVO_REGISTRO.read_text(encoding="utf-8").splitlines()
    for linea in lineas[-6:]:
        e = json.loads(linea)
        print(f"{e['fecha']}  {e['resultado']:<11} {e['codigo'] or '-':<4} {e['url']}")