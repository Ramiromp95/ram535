"""
biblioteca.py
La biblioteca de RAM535. Fichas de los artefactos del usuario en biblioteca\\biblioteca.db.
No sale a internet y no ejecuta nada. La IA solo la puede leer.

Paso 6.2. Revisar los archivos exportados, importar con aprobación y buscar.
Paso 6.3. La revisión da hasta 5 títulos de ejemplo de nuevas, cambiadas y eliminadas.
Paso 6.4. Las palabras vacías (qué, es, cómo...) no cuentan en la búsqueda.
Paso 6.5. Índice de conexiones por identificadores y correlación calculada por el programa.
Paso 6.6. Auditoría. Se importa lo mismo que se revisó (H-11) e identificadores propios validados.
Paso 7.1. Salas de TryHackMe relacionadas y la siguiente sala de cada ruta, para el modo profesor.
Paso 12.1. Fuentes oficiales de threat hunting, red team y bug bounty (Sigma, Atomic Red Team, LOLBAS,
GTFOBins, OWASP WSTG y API Top 10, CAPEC y CWE). Identificadores CWE, CAPEC, WSTG y API, y conexiones
que añaden una ficha de cada fuente complementaria.
"""

import hashlib
import json
import re
import sqlite3
import threading
from collections import Counter
from datetime import datetime
from pathlib import Path

from limpiar import quitar_invisibles
from memoria import _comprimir, _descomprimir, _huella, _palabras, _sin_tildes

CARPETA = Path(__file__).resolve().parent / "biblioteca"
ARCHIVO = CARPETA / "biblioteca.db"

# Solo se aceptan estos archivos, y cada uno solo con claves de su prefijo.
ARTEFACTOS = {
    "dossier": "dossier:",
    "libro_cves": "libro:",
    "mitre": "mitre:",
    "tryhackme": "thm:",
    # Paso 12.1. Fuentes oficiales que prepara Claude desde sus repositorios.
    "sigma": "sigma:",
    "atomic": "atomic:",
    "lolbas": "lolbas:",
    "gtfobins": "gtfo:",
    "wstg": "wstg:",
    "owasp_api": "owaspapi:",
    "capec": "capec:",
    "cwe": "cwe:",
}
# Tus fichas. Todo lo demás es oficial.
PROPIAS = ("dossier:", "libro:", "thm:", "mitre:mapa:")
# Cómo se presenta cada fuente oficial a la IA.
ORIGENES = {
    "mitre": "base oficial de MITRE",
    "sigma": "regla oficial de SigmaHQ",
    "atomic": "prueba oficial de Atomic Red Team",
    "lolbas": "ficha oficial de LOLBAS",
    "gtfobins": "ficha oficial de GTFOBins",
    "wstg": "guía oficial OWASP WSTG",
    "owasp_api": "OWASP API Security Top 10",
    "capec": "catálogo oficial CAPEC de MITRE",
    "cwe": "catálogo oficial CWE de MITRE",
}
# Fuentes que acompañan a un identificador en las conexiones, en este orden.
COMPLEMENTOS = ["sigma", "atomic", "lolbas", "gtfobins", "capec", "owasp_api", "wstg", "cwe"]
MAX_COMPLEMENTOS = 3             # Fichas complementarias como mucho por identificador
# Si hay que elegir una ficha oficial por su título, primero las de referencia y al final las reglas.
RANGO_TITULO = {"mitre": 0, "cwe": 1, "capec": 1, "wstg": 1, "owasp_api": 1, "lolbas": 2, "gtfobins": 2,
                "atomic": 3, "sigma": 4}
# Prefijos cuya clave termina en el identificador que definen (cwe:CWE-79).
DEFINEN = ("capec:", "cwe:", "wstg:", "owaspapi:")
FORMATO = "biblioteca-ram535/1"
MAX_ARCHIVO = 20 * 1024 * 1024   # Bytes como mucho por archivo exportado
MAX_FICHAS = 20_000              # Fichas como mucho por archivo
MAX_TEXTO = 50_000               # Caracteres como mucho por ficha
MAX_RESULTADOS = 3
MAX_CONEXIONES = 10              # Fichas relacionadas como mucho en cada consulta
MAX_IDENTIFICADORES = 6          # Identificadores que se siguen en cada consulta
LARGO_RESUMEN = 350              # Caracteres del resumen de cada conexión
MAX_CANDIDATOS = 40              # Se ordenan los 40 mejores y se dan las tuyas primero
PESOS = "10.0, 4.0, 1.0"         # Importancia del título, las etiquetas y el texto al ordenar

# Identificadores que se buscan por su clave exacta antes que por palabras.
PATRON_ID = re.compile(
    r"\b(CVE-\d{4}-\d{4,}|AML\.(?:TA|T|M|CS)\d{4}(?:\.\d{3})?|TA\d{4}|T\d{4}(?:\.\d{3})?"
    r"|[GSMC]\d{4}|DET\d{4}|D3-[A-Z]{2,}|CAR-\d{4}-\d{2}-\d{3}"
    r"|CWE-\d{1,5}|CAPEC-\d{1,5}|WSTG-[A-Z]{4}-\d{2}|API\d{1,2}:20\d{2})\b",
    re.IGNORECASE,
)

# Paso 12.7. Grupos, software y campañas de ATT&CK.
_ENTIDAD = re.compile(r"mitre:(?:enterprise|mobile|ics):[GSC]\d{4}")

# Palabras que no aportan nada a una búsqueda. Se quitan si queda alguna otra.
VACIAS = set("""
a al algo como cual cuales cuando de del dime donde el ella en es esta este explica explicame
hay la las le lo los me mi o para por porque que quien se sobre son su sus te tu un una y
the of and to in is a an what how does do with for on
ataque ataques concepto significa funciona sirve busca buscar dame quiero necesito puedes
sala salas tryhackme thm detalladamente manera forma modo explicame enseñame ensename entrar
cazo cazar caza cazas detecto detectar detectarlo detecta emulo emular emula pruebo probarlo hago hacer
pongo poner pon elijo elegir escribo escribir redacto redactar
grupo grupos información informacion internet más mas toda todo todas todos posible
which what who whom whose when where why how is are was were be been being do does did the an and or
of to in on at for with by from as that this these those it its both either neither any all some most
more can could should would will may might has have had into about between than then also not your
you my our their there here leverage leverages leveraging
""".split())


def _en_titulo(titulo, palabras):
    """Ajuste 7.3b. Cuánto encaja el título con la consulta (sin tildes ni mayúsculas).
    2 si tiene todas las palabras, 1 si el título es exactamente una de ellas (una sala
    llamada XSS o un término del glosario), 0 en otro caso. Contar palabras sueltas subía
    fichas que solo compartían una palabra común, como «memoria» en los CVE."""
    tokens = re.findall(r"\w+", _sin_tildes(titulo or ""))
    junto = " " + " ".join(tokens) + " "
    claves = [" ".join(re.findall(r"\w+", _sin_tildes(p))) for p in palabras]
    claves = [k for k in claves if k]
    if claves and all(f" {k} " in junto for k in claves):
        return 2
    return 1 if " ".join(tokens) in claves else 0


def _relevantes(con, filas, exactas, palabras, maximo):
    """Ajuste 7.5b. Quita las fichas que solo comparten palabras sueltas con la consulta.
    Si una palabra de la consulta no aparece en ninguna ficha, es el tema y la biblioteca no lo
    tiene, así que solo valen las encontradas por identificador. Las demás deben tener la
    consulta en el título o al menos la mitad de sus palabras en el texto."""
    if len(palabras) >= 2:
        for p in palabras:
            if not con.execute("SELECT 1 FROM busqueda WHERE busqueda MATCH ? LIMIT 1", (f'"{p}"',)).fetchone():
                return [f for f in filas if f[0] in exactas][:maximo]
    claves = [" ".join(re.findall(r"\w+", _sin_tildes(p))) for p in palabras]
    necesarias = (len(claves) + 1) // 2
    elegidas = []
    for f in filas:
        if len(elegidas) >= maximo:
            break
        if f[0] in exactas or _en_titulo(f[4], palabras):
            elegidas.append(f)
            continue
        junto = " " + " ".join(re.findall(r"\w+", _sin_tildes(f[4] + " " + _descomprimir(f[7])))) + " "
        if sum(1 for k in claves if k and f" {k} " in junto) >= necesarias:
            elegidas.append(f)
    return elegidas


def _candidatos(con, columnas, comillas, palabras, filtro="", limite=MAX_CANDIDATOS):
    """Ajuste 7.3. Busca con cualquiera de las palabras (OR) y pone delante las fichas que
    tienen más palabras de la consulta en el título. Antes se buscaba primero con todas (AND)
    y una sala titulada XSS quedaba fuera si no decía «almacenado»."""
    filas = con.execute(
        f"SELECT {columnas} FROM busqueda JOIN fichas AS f ON f.id = busqueda.rowid "
        f"WHERE busqueda MATCH ? {filtro} ORDER BY bm25(busqueda, {PESOS}) LIMIT ?",
        (" OR ".join(comillas), limite),
    ).fetchall()
    # sorted es estable. Se conserva el orden de bm25 dentro de cada grupo.
    return sorted(filas, key=lambda f: -_en_titulo(f[1], palabras))

ESQUEMA = """
CREATE TABLE IF NOT EXISTS fichas (
    id         INTEGER PRIMARY KEY,
    clave      TEXT NOT NULL UNIQUE,
    artefacto  TEXT NOT NULL,
    coleccion  TEXT NOT NULL,
    titulo     TEXT NOT NULL,
    etiquetas  TEXT NOT NULL,
    fuente     TEXT NOT NULL,
    propia     INTEGER NOT NULL,
    huella     TEXT NOT NULL,
    texto      BLOB NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS busqueda USING fts5 (
    titulo, etiquetas, texto,
    content = '',
    contentless_delete = 1,
    tokenize = 'unicode61 remove_diacritics 2'
);
CREATE TABLE IF NOT EXISTS enlaces (
    ficha_id   INTEGER NOT NULL,
    ident      TEXT NOT NULL,
    propio     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS enlaces_por_ident ON enlaces (ident);
CREATE INDEX IF NOT EXISTS enlaces_por_ficha ON enlaces (ficha_id);
CREATE TABLE IF NOT EXISTS archivos (
    artefacto  TEXT PRIMARY KEY,
    titulo     TEXT NOT NULL,
    url        TEXT NOT NULL,
    exportado  TEXT NOT NULL,
    huella     TEXT NOT NULL,
    total      INTEGER NOT NULL,
    importado  TEXT NOT NULL
);
"""


class ErrorBiblioteca(Exception):
    """Un archivo exportado que no se puede importar. El mensaje se puede enseñar en la ventana."""


def _cadena(valor, nombre, maximo):
    if not isinstance(valor, str) or not valor.strip() or len(valor) > maximo:
        raise ErrorBiblioteca(f"{nombre} no es válido.")
    return quitar_invisibles(valor).strip()


def _ficha(dato, prefijo, artefacto):
    """Comprueba una ficha y la deja lista para guardar."""
    if not isinstance(dato, dict):
        raise ErrorBiblioteca("Hay una ficha que no tiene formato de ficha.")
    clave = _cadena(dato.get("clave"), "Una clave", 500)
    if not clave.startswith(prefijo):
        raise ErrorBiblioteca(f"La ficha {clave[:80]} no pertenece a este artefacto.")
    etiquetas = dato.get("etiquetas", [])
    if not isinstance(etiquetas, list) or len(etiquetas) > 20:
        raise ErrorBiblioteca(f"Las etiquetas de {clave[:80]} no son válidas.")
    etiquetas = [_cadena(e, "Una etiqueta", 200) for e in etiquetas if isinstance(e, str) and e.strip()]
    ficha = {
        "clave": clave,
        "artefacto": artefacto,
        "coleccion": _cadena(dato.get("coleccion"), "Una colección", 100),
        "titulo": _cadena(dato.get("titulo"), "Un título", 300),
        "etiquetas": etiquetas,
        "fuente": _cadena(dato.get("fuente"), "Una fuente", 2000),
        "texto": _cadena(dato.get("texto"), "Un texto", MAX_TEXTO),
    }
    # Tus fichas son las de tus artefactos. MITRE y las demás fuentes son oficiales (tus mapas sí son tuyos).
    ficha["propia"] = int(clave.startswith(PROPIAS))
    ficha["huella"] = _huella(json.dumps(
        [ficha["coleccion"], ficha["titulo"], ficha["etiquetas"], ficha["fuente"], ficha["texto"]],
        ensure_ascii=False))
    return ficha


def _ident_propio(clave):
    """El identificador que define una ficha. libro:CVE-2021-44228 o mitre:enterprise:T1059."""
    ident = None
    if clave.startswith("libro:"):
        ident = clave[6:].upper()
    elif clave.startswith("mitre:") and not clave.startswith("mitre:mapa:"):
        ident = clave.rsplit(":", 1)[-1].upper()
    elif clave.startswith(DEFINEN):
        ident = clave.split(":", 1)[1].upper()
    # Solo vale si tiene forma de identificador. Una clave rara no se convierte en consulta.
    return ident if ident and PATRON_ID.fullmatch(ident) else None


def _enlazar(con, ficha_id, clave, titulo, etiquetas, texto):
    """Apunta qué identificadores cita una ficha y cuál la define."""
    propio = _ident_propio(clave)
    citados = {i.upper() for i in PATRON_ID.findall(" ".join([titulo, " ".join(etiquetas), texto]))}
    citados.discard(propio)
    filas = [(ficha_id, i, 0) for i in citados]
    if propio:
        filas.append((ficha_id, propio, 1))
    con.executemany("INSERT INTO enlaces (ficha_id, ident, propio) VALUES (?, ?, ?)", filas)


def _resumen(texto):
    """El primer párrafo con contenido, cortado. En MITRE es la descripción."""
    partes = texto.split("\n\n")
    cuerpo = partes[1] if len(partes) > 1 and len(partes[1]) > 80 else texto
    cuerpo = " ".join(cuerpo.split())
    return cuerpo if len(cuerpo) <= LARGO_RESUMEN else cuerpo[:LARGO_RESUMEN].rsplit(" ", 1)[0] + " [...]"


def leer_exportado(ruta):
    """Lee un archivo exportado, comprueba su huella y cada ficha. Devuelve (cabecera, fichas)."""
    artefacto = ruta.stem
    if artefacto not in ARTEFACTOS:
        raise ErrorBiblioteca(f"{ruta.name} no es un archivo de la biblioteca.")
    if ruta.stat().st_size > MAX_ARCHIVO:
        raise ErrorBiblioteca(f"{ruta.name} es demasiado grande.")
    try:
        datos = json.loads(ruta.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ErrorBiblioteca(f"{ruta.name} no se puede leer.") from None
    if not isinstance(datos, dict) or datos.get("formato") != FORMATO or datos.get("artefacto") != artefacto:
        raise ErrorBiblioteca(f"{ruta.name} no tiene el formato de la biblioteca.")
    fichas = datos.get("fichas")
    if not isinstance(fichas, list) or not fichas or len(fichas) > MAX_FICHAS or datos.get("total") != len(fichas):
        raise ErrorBiblioteca(f"{ruta.name} no tiene un número de fichas válido.")
    # La huella se calcula igual que el exportador. Si no coincide, alguien cambió el archivo.
    cuerpo = json.dumps(fichas, ensure_ascii=False, sort_keys=True)
    if hashlib.sha256(cuerpo.encode("utf-8")).hexdigest() != datos.get("huella"):
        raise ErrorBiblioteca(f"La huella de {ruta.name} no coincide. El archivo se ha cambiado después de exportarlo.")
    limpias = [_ficha(f, ARTEFACTOS[artefacto], artefacto) for f in fichas]
    if len({f["clave"] for f in limpias}) != len(limpias):
        raise ErrorBiblioteca(f"{ruta.name} tiene claves repetidas.")
    cabecera = {
        "artefacto": artefacto,
        "titulo": _cadena(datos.get("titulo"), "El título", 100),
        "url": _cadena(datos.get("url"), "La dirección", 300),
        "exportado": _cadena(datos.get("exportado"), "La fecha", 40),
        "huella": datos["huella"],
        "total": len(limpias),
    }
    return cabecera, limpias


class Biblioteca:
    """Revisar e importar los archivos exportados, y buscar en solo lectura."""

    def __init__(self, archivo=ARCHIVO, carpeta=CARPETA):
        self.archivo = Path(archivo).resolve()
        self.carpeta = Path(carpeta).resolve()
        self._candado = threading.Lock()
        self.carpeta.mkdir(parents=True, exist_ok=True)
        self.archivo.parent.mkdir(parents=True, exist_ok=True)
        nueva = not self.archivo.exists()
        con = self._escribir()
        try:
            if nueva:
                con.execute("PRAGMA auto_vacuum = FULL")
            con.executescript(ESQUEMA)
            version = con.execute("PRAGMA user_version").fetchone()[0]
            # Paso 12.1. La versión 3 reconoce CWE, CAPEC, WSTG y API. Los enlaces de las fichas
            # que ya estaban se rehacen una sola vez para que también los tengan.
            self._reconstruir_enlaces(con, rehacer=0 < version < 3)
            con.execute("PRAGMA user_version = 3")
        finally:
            con.close()

    def _reconstruir_enlaces(self, con, rehacer=False):
        """Una biblioteca importada antes del paso 6.5 no tiene enlaces. Se crean una sola vez.
        Con rehacer, se borran y se vuelven a crear (cuando cambia qué identificadores se reconocen)."""
        hay_fichas = con.execute("SELECT 1 FROM fichas LIMIT 1").fetchone()
        hay_enlaces = con.execute("SELECT 1 FROM enlaces LIMIT 1").fetchone()
        if hay_fichas and (rehacer or not hay_enlaces):
            with con:
                con.execute("DELETE FROM enlaces")
                for ident, clave, titulo, etiquetas, blob in con.execute(
                        "SELECT id, clave, titulo, etiquetas, texto FROM fichas").fetchall():
                    _enlazar(con, ident, clave, titulo, json.loads(etiquetas), _descomprimir(blob))

    def _ajustes(self, con):
        con.execute("PRAGMA trusted_schema = OFF")
        con.execute("PRAGMA cell_size_check = ON")
        con.execute("PRAGMA temp_store = MEMORY")
        return con

    def _escribir(self):
        """Conexión con permiso de escritura. Solo la usan revisar e importar."""
        con = sqlite3.connect(self.archivo, timeout=5)
        con.execute("PRAGMA secure_delete = ON")
        return self._ajustes(con)

    def _leer(self):
        """Conexión de solo lectura. Es la que usa la IA. SQLite rechaza cualquier escritura."""
        return self._ajustes(sqlite3.connect(self.archivo.as_uri() + "?mode=ro", uri=True, timeout=5))

    # ---------- Revisar e importar ----------

    def revisar(self, _leidas=None):
        """Compara los archivos exportados con lo que hay en la biblioteca, sin cambiar nada.
        Devuelve el resumen por artefacto y una señal que importar exige.
        Si llega _leidas, guarda ahí las fichas leídas para que importar use exactamente esas."""
        con = self._leer()
        try:
            actuales = {}
            for clave, artefacto, huella, titulo in con.execute("SELECT clave, artefacto, huella, titulo FROM fichas"):
                actuales.setdefault(artefacto, {})[clave] = (huella, titulo)
            importados = {a: h for a, h in con.execute("SELECT artefacto, huella FROM archivos")}
        finally:
            con.close()

        resumen, errores, huellas = [], [], []
        for artefacto in ARTEFACTOS:
            ruta = self.carpeta / f"{artefacto}.json"
            if not ruta.exists():
                continue
            try:
                cabecera, fichas = leer_exportado(ruta)
            except ErrorBiblioteca as error:
                errores.append(str(error))
                continue
            if _leidas is not None:
                _leidas[artefacto] = fichas
            antes = actuales.get(artefacto, {})
            nuevas = [f for f in fichas if f["clave"] not in antes]
            cambiadas = [f for f in fichas if f["clave"] in antes and antes[f["clave"]][0] != f["huella"]]
            claves = {f["clave"] for f in fichas}
            eliminadas = [c for c in antes if c not in claves]
            huellas.append(f"{artefacto}:{cabecera['huella']}")
            resumen.append({
                **cabecera,
                "nuevas": len(nuevas), "cambiadas": len(cambiadas), "eliminadas": len(eliminadas),
                "iguales": len(fichas) - len(nuevas) - len(cambiadas),
                "ejemplos_nuevas": [f["titulo"] for f in nuevas[:5]],
                "ejemplos_cambiadas": [f["titulo"] for f in cambiadas[:5]],
                "ejemplos_eliminadas": [antes[c][1] for c in eliminadas[:5]],
                "ya_importado": importados.get(artefacto) == cabecera["huella"],
            })
        senal = hashlib.sha256("|".join(huellas).encode("utf-8")).hexdigest()
        pendiente = any(r["nuevas"] or r["cambiadas"] or r["eliminadas"] for r in resumen)
        return {"resumen": resumen, "errores": errores, "senal": senal, "pendiente": pendiente}

    def importar(self, senal):
        """Aplica exactamente lo que se revisó. Si los archivos cambiaron, no hace nada."""
        with self._candado:
            # Los archivos se leen una sola vez. Lo que se comprueba es lo que se importa (H-11).
            leidas = {}
            revision = self.revisar(leidas)
            if not isinstance(senal, str) or senal != revision["senal"]:
                raise ErrorBiblioteca("Los archivos han cambiado desde la revisión. Vuelve a revisarlos.")
            if revision["errores"]:
                raise ErrorBiblioteca("Hay archivos con errores. Corrígelos antes de importar.")
            ahora = datetime.now().astimezone().isoformat(timespec="seconds")
            con = self._escribir()
            try:
                with con:
                    for cabecera in revision["resumen"]:
                        self._aplicar(con, cabecera["artefacto"], leidas[cabecera["artefacto"]])
                        con.execute(
                            "INSERT OR REPLACE INTO archivos (artefacto, titulo, url, exportado, huella, total, importado) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (cabecera["artefacto"], cabecera["titulo"], cabecera["url"], cabecera["exportado"],
                             cabecera["huella"], cabecera["total"], ahora),
                        )
                    con.execute("INSERT INTO busqueda (busqueda) VALUES ('optimize')")
            finally:
                con.close()
        return self.estado()

    def _aplicar(self, con, artefacto, fichas):
        antes = {c: (i, h) for i, c, h in con.execute(
            "SELECT id, clave, huella FROM fichas WHERE artefacto = ?", (artefacto,))}
        claves = set()
        for f in fichas:
            claves.add(f["clave"])
            previa = antes.get(f["clave"])
            if previa and previa[1] == f["huella"]:
                continue
            if previa:
                con.execute("DELETE FROM busqueda WHERE rowid = ?", (previa[0],))
                con.execute("DELETE FROM enlaces WHERE ficha_id = ?", (previa[0],))
                con.execute("DELETE FROM fichas WHERE id = ?", (previa[0],))
            cursor = con.execute(
                "INSERT INTO fichas (clave, artefacto, coleccion, titulo, etiquetas, fuente, propia, huella, texto) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (f["clave"], artefacto, f["coleccion"], f["titulo"], json.dumps(f["etiquetas"], ensure_ascii=False),
                 f["fuente"], f["propia"], f["huella"], _comprimir(f["texto"])),
            )
            con.execute(
                "INSERT INTO busqueda (rowid, titulo, etiquetas, texto) VALUES (?, ?, ?, ?)",
                (cursor.lastrowid, f["titulo"], " ".join(f["etiquetas"]), f["texto"]),
            )
            _enlazar(con, cursor.lastrowid, f["clave"], f["titulo"], f["etiquetas"], f["texto"])
        for clave, (ident, _) in antes.items():
            if clave not in claves:
                con.execute("DELETE FROM busqueda WHERE rowid = ?", (ident,))
                con.execute("DELETE FROM enlaces WHERE ficha_id = ?", (ident,))
                con.execute("DELETE FROM fichas WHERE id = ?", (ident,))

    # ---------- Buscar (solo lectura) ----------

    def buscar(self, consulta, maximo=MAX_RESULTADOS):
        """Primero los identificadores exactos (CVE, T1059, G0016...). Después por palabras,
        con tus fichas por delante de las oficiales dentro de los mejores resultados."""
        if not isinstance(consulta, str):
            return []
        maximo = max(1, min(int(maximo), MAX_RESULTADOS))
        columnas = "f.id, f.clave, f.artefacto, f.coleccion, f.titulo, f.fuente, f.propia, f.texto"
        con = self._leer()
        try:
            filas, vistos = [], set()
            for ident in dict.fromkeys(i.upper() for i in PATRON_ID.findall(consulta)):
                for fila in con.execute(
                    f"SELECT {columnas} FROM fichas AS f WHERE f.clave = ? OR f.clave LIKE ? ESCAPE '\\' "
                    "OR f.clave IN (" + ",".join("?" * len(DEFINEN)) + ") "
                    "ORDER BY f.propia DESC, f.id LIMIT 2",
                    (f"libro:{ident}", "mitre:%:" + ident.replace("_", "\\_").replace("%", "\\%"),
                     *(p + ident for p in DEFINEN)),
                ):
                    if fila[0] not in vistos:
                        vistos.add(fila[0])
                        filas.append(fila)
            exactas = {f[0] for f in filas}
            # Paso 12.1. Si ya hay fichas por identificador, el identificador no se busca también
            # como palabras sueltas (API1:2023 no debe traer todo lo que dice 2023).
            palabras = _palabras(PATRON_ID.sub(" ", consulta)) if filas else _palabras(consulta)
            # Paso 12.7. El nombre de lo ya encontrado por identificador tampoco se busca como palabra.
            # G0020 Equation no debe traer otros grupos que solo citan «Equation Editor» en su texto.
            nombres = {t for f in filas for t in re.findall(r"\w+", _sin_tildes(f[4]))}
            utiles = [p for p in palabras if p.lower() not in VACIAS and _sin_tildes(p) not in VACIAS
                      and _sin_tildes(p) not in nombres]
            # Paso 12.7. Si ya hay fichas por identificador y no queda ninguna palabra útil, no se busca
            # nada más. Antes se buscaban las palabras vacías y salía ruido.
            palabras = utiles or ([] if filas else palabras)
            candidatos = []
            if palabras and len(filas) < maximo:
                comillas = [f'"{p}"' for p in palabras]
                orden = "f.id, f.titulo, f.clave, f.artefacto, f.coleccion, f.fuente, f.propia, f.texto"
                candidatos = [(f[0], f[2], f[3], f[4], f[1], f[5], f[6], f[7])
                              for f in _candidatos(con, orden, comillas, palabras)]
                # Primero las tuyas y, dentro de cada grupo, las que tienen más palabras en el título.
                candidatos.sort(key=lambda f: (-f[6], -_en_titulo(f[4], palabras)))
                # Paso 12.1. Como mucho una ficha de cada fuente complementaria, para que cientos
                # de reglas o pruebas parecidas no tapen tus fichas ni las de MITRE.
                por_fuente = Counter()
                for fila in candidatos:
                    if fila[0] in vistos:
                        continue
                    if fila[2] in COMPLEMENTOS:  # fila[2] es el artefacto
                        if por_fuente[fila[2]]:
                            continue
                        por_fuente[fila[2]] += 1
                    vistos.add(fila[0])
                    filas.append(fila)
            filas = _relevantes(con, filas, exactas, palabras, maximo)
            # Paso 12.7. Si un grupo, software o campaña de ATT&CK lleva en el título todo lo que preguntas,
            # sobran los demás grupos, software o campañas que solo lo citan en su texto.
            def nombrada(f):
                return f[0] in exactas or _en_titulo(f[4], palabras) == 2

            if any(_ENTIDAD.fullmatch(f[1]) and nombrada(f) for f in filas):
                filas = [f for f in filas if not _ENTIDAD.fullmatch(f[1]) or nombrada(f)]
            # Paso 12.1. Tus fichas van primero, pero si una ficha oficial lleva en el título justo lo
            # que preguntas (certutil, find, una regla concreta) y no ha entrado, ocupa el último hueco.
            if palabras and filas and not any(not f[6] and _en_titulo(f[4], palabras) for f in filas):
                elegidas = {f[0] for f in filas}
                titulada = max((f for f in candidatos if not f[6] and f[0] not in elegidas
                                and _en_titulo(f[4], palabras)),
                               key=lambda f: (_en_titulo(f[4], palabras), -RANGO_TITULO.get(f[2], 5)), default=None)
                if titulada:
                    if len(filas) >= maximo:
                        quitar = next((i for i in range(len(filas) - 1, -1, -1) if filas[i][0] not in exactas), None)
                        if quitar is not None:
                            filas = filas[:quitar] + filas[quitar + 1:]
                    if len(filas) < maximo:
                        filas.append(titulada)
            exportados = {a: e for a, e in con.execute("SELECT artefacto, exportado FROM archivos")}
        finally:
            con.close()
        return [
            {"id": f[0], "clave": f[1], "artefacto": f[2], "coleccion": f[3], "titulo": f[4], "fuente": f[5],
             "propia": bool(f[6]), "texto": _descomprimir(f[7]), "exportado": exportados.get(f[2], "")}
            for f in filas
        ]

    def salas(self, consulta, maximo=2):
        """Salas de TryHackMe relacionadas con la consulta, con dónde están y la siguiente de su ruta.
        Lo calcula el programa a partir del mapa del usuario. Solo lectura."""
        if not isinstance(consulta, str):
            return []
        palabras = _palabras(consulta)
        utiles = [p for p in palabras if p.lower() not in VACIAS and _sin_tildes(p) not in VACIAS]
        palabras = utiles or palabras
        if not palabras:
            return []
        comillas = [f'"{p}"' for p in palabras]
        con = self._leer()
        try:
            filas = _candidatos(con, "f.id, f.titulo, f.fuente, f.texto", comillas, palabras,
                                "AND f.clave LIKE 'thm:sala:%'", 20)[:max(1, min(int(maximo), 3))]
            resultado = []
            for _id, titulo, fuente, blob in filas:
                texto = _descomprimir(blob)
                donde = next((l[len("Dónde está "):] for l in texto.split("\n") if l.startswith("Dónde está ")), "")
                primera = donde.split(";")[0].strip()
                camino, _, seccion = primera.partition(" · ")
                resultado.append({"titulo": titulo, "fuente": fuente, "donde": donde,
                                  "siguiente": self._siguiente(con, titulo, camino, seccion)})
        finally:
            con.close()
        return resultado

    def _siguiente(self, con, sala, camino, seccion):
        """La sala que va después en la ruta del usuario. None si es la última o no se encuentra."""
        fila = con.execute(
            "SELECT texto FROM fichas WHERE clave LIKE 'thm:path:%' AND titulo = ?", (camino,)).fetchone()
        if not fila:
            return None
        bloques = [b.split("\n") for b in _descomprimir(fila[0]).split("\n\n")]
        orden = [(b[0], l[2:]) for b in bloques for l in b[1:] if l.startswith("- ")]
        for i, (sec, nombre) in enumerate(orden):
            if nombre == sala and sec == seccion and i + 1 < len(orden):
                return {"sala": orden[i + 1][1], "seccion": orden[i + 1][0]}
        return None

    def conexiones(self, fichas, maximo=MAX_CONEXIONES):
        """Lo relacionado con las fichas encontradas, siguiendo sus identificadores.
        Por cada identificador da su ficha de definición y hasta 2 fichas tuyas que lo citan.
        Devuelve {"identificadores": [...], "fichas": [...]}. Solo lectura."""
        ids = [f["id"] for f in fichas if isinstance(f.get("id"), int)]
        if not ids:
            return {"identificadores": [], "fichas": []}
        con = self._leer()
        try:
            marcas = ",".join("?" * len(ids))
            propios, citados = [], Counter()
            for ident, propio in con.execute(
                    f"SELECT ident, propio FROM enlaces WHERE ficha_id IN ({marcas})", ids):
                if propio:
                    propios.append(ident)
                elif not ident.startswith(("TA", "AML.TA")):  # Las tácticas aportan poco aquí
                    citados[ident] += 1
            orden = list(dict.fromkeys(propios + [i for i, _ in citados.most_common()]))[:MAX_IDENTIFICADORES]

            resultado, vistos = [], set(ids)
            for ident in orden:
                definida = False
                citas = 0
                origen_definicion = None
                filas = list(con.execute(
                        "SELECT f.id, f.clave, f.coleccion, f.titulo, f.propia, f.texto, e.propio, f.artefacto "
                        "FROM enlaces AS e JOIN fichas AS f ON f.id = e.ficha_id "
                        "WHERE e.ident = ? ORDER BY e.propio DESC, f.propia DESC, f.id LIMIT 12", (ident,)))
                # Paso 12.1. Una ficha de cada fuente complementaria que cita el identificador, como
                # mucho tres. Cada fuente viene ordenada de mejor a peor, así que vale la primera.
                extra = 0
                for fuente in COMPLEMENTOS:
                    if extra >= MAX_COMPLEMENTOS:
                        break
                    fila = con.execute(
                        "SELECT f.id, f.clave, f.coleccion, f.titulo, f.propia, f.texto, e.propio, f.artefacto "
                        "FROM enlaces AS e JOIN fichas AS f ON f.id = e.ficha_id "
                        "WHERE e.ident = ? AND e.propio = 0 AND f.artefacto = ? ORDER BY f.id LIMIT 1",
                        (ident, fuente)).fetchone()
                    if fila:
                        filas.append(fila + ("complemento",))
                        extra += 1
                for fila in filas:
                    if fila[6]:
                        if fila[0] in vistos or definida:
                            definida = True
                            continue
                        definida = True
                        origen_definicion = fila[7]
                    elif fila[0] in vistos:
                        continue
                    elif len(fila) > 8:
                        if fila[7] == origen_definicion:
                            continue  # La definición ya representa a esa fuente
                    elif not fila[4] or citas >= 2:
                        continue  # De lo demás, solo citas de fichas tuyas
                    else:
                        citas += 1
                    vistos.add(fila[0])
                    resultado.append({
                        "clave": fila[1], "coleccion": fila[2], "titulo": fila[3], "propia": bool(fila[4]),
                        "artefacto": fila[7], "via": ident, "resumen": _resumen(_descomprimir(fila[5])),
                    })
                    if len(resultado) >= maximo:
                        return {"identificadores": orden, "fichas": resultado}
        finally:
            con.close()
        return {"identificadores": orden, "fichas": resultado}

    def estado(self):
        con = self._leer()
        try:
            archivos = [
                {"artefacto": a, "titulo": t, "exportado": e, "total": n, "importado": i}
                for a, t, e, n, i in con.execute(
                    "SELECT artefacto, titulo, exportado, total, importado FROM archivos ORDER BY artefacto")
            ]
            total = con.execute("SELECT COUNT(*) FROM fichas").fetchone()[0]
            paginas = con.execute("PRAGMA page_count").fetchone()[0] * con.execute("PRAGMA page_size").fetchone()[0]
        finally:
            con.close()
        return {"fichas": total, "mb": round(paginas / (1024 * 1024), 2), "archivos": archivos}


# ---------- Prueba suelta ----------

def _exportado(carpeta, artefacto, fichas, cambiar_huella=False):
    """Crea un archivo exportado igual que el exportador, para las pruebas."""
    cuerpo = json.dumps(fichas, ensure_ascii=False, sort_keys=True)
    huella = hashlib.sha256(cuerpo.encode("utf-8")).hexdigest()
    datos = {"formato": FORMATO, "artefacto": artefacto, "titulo": artefacto, "url": "https://claude.ai/artifact/x",
             "exportado": "2026-10-21", "total": len(fichas), "huella": "0" * 64 if cambiar_huella else huella,
             "fichas": fichas}
    (Path(carpeta) / f"{artefacto}.json").write_text(json.dumps(datos, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    import sys
    import tempfile

    if sys.argv[1:] == ["revisar"]:
        # Solo mira. No importa nada.
        r = Biblioteca().revisar()
        for a in r["resumen"]:
            print(f"{a['titulo']:20} exportado {a['exportado']}  {a['total']:5} fichas  "
                  f"nuevas {a['nuevas']}  cambiadas {a['cambiadas']}  eliminadas {a['eliminadas']}  iguales {a['iguales']}")
        for e in r["errores"]:
            print("ERROR", e)
        print("Hay cambios para importar" if r["pendiente"] else "La biblioteca está al día")
        sys.exit()

    def ver(nombre, correcto):
        print(f"  {'OK   ' if correcto else 'FALLO'}  {nombre}")
        return correcto

    def f(clave, titulo, texto, coleccion="Prueba"):
        return {"clave": clave, "coleccion": coleccion, "titulo": titulo, "etiquetas": [], "texto": texto,
                "fuente": "https://claude.ai/artifact/x"}

    print("Prueba de biblioteca.py en una carpeta temporal. Tu biblioteca real no se toca.")
    with tempfile.TemporaryDirectory() as tmp:
        todo = []
        _exportado(tmp, "dossier", [f("dossier:case-zeus", "ZeuS", "Malware bancario con webinjects y phishing")])
        _exportado(tmp, "mitre", [
            f("mitre:enterprise:T1566", "T1566 Phishing", "Adversaries may send phishing messages"),
            f("mitre:mapa:m01", "SolarWinds", "APT29 y una actualización troyanizada con phishing previo"),
        ])
        _exportado(tmp, "libro_cves", [f("libro:CVE-2024-3400", "CVE-2024-3400 PAN-OS", "Inyección de comandos")])
        (Path(tmp) / "otro.json").write_text("{}", encoding="utf-8")
        b = Biblioteca(Path(tmp) / "b.db", tmp)

        r = b.revisar()
        todo.append(ver("La primera revisión ve 4 fichas nuevas", sum(a["nuevas"] for a in r["resumen"]) == 4))
        todo.append(ver("Un archivo que no es de la biblioteca se ignora", len(r["resumen"]) == 3 and not r["errores"]))
        todo.append(ver("Revisar no importa nada", b.estado()["fichas"] == 0))
        try:
            b.importar("señal inventada")
            colada = True
        except ErrorBiblioteca:
            colada = False
        todo.append(ver("Sin la señal de la revisión no se importa", not colada and b.estado()["fichas"] == 0))
        e = b.importar(r["senal"])
        todo.append(ver("Importar con la señal correcta", e["fichas"] == 4 and len(e["archivos"]) == 3))
        todo.append(ver("La segunda revisión ve todo igual", not b.revisar()["pendiente"]))

        todo.append(ver("Buscar un CVE por su identificador", b.buscar("¿qué es CVE-2024-3400?")[0]["clave"] == "libro:CVE-2024-3400"))
        todo.append(ver("Buscar una técnica por su identificador", b.buscar("explícame T1566")[0]["clave"] == "mitre:enterprise:T1566"))
        orden = [x["clave"] for x in b.buscar("phishing")]
        todo.append(ver("Tus fichas salen antes que las oficiales",
                        orden.index("mitre:enterprise:T1566") > orden.index("dossier:case-zeus")
                        and orden.index("mitre:enterprise:T1566") > orden.index("mitre:mapa:m01")))
        todo.append(ver("Un tema que no está en ninguna ficha no trae fichas al azar (7.5b)",
                        not b.buscar("ZeuS webinjects inexistente")))
        todo.append(ver("Buscar sin tilde encuentra con tilde", b.buscar("actualizacion")[0]["clave"] == "mitre:mapa:m01"))
        try:
            b.buscar("'); DROP TABLE fichas; -- \" NEAR(* ^ T1566%")
            sigue = b.estado()["fichas"] == 4
        except Exception:
            sigue = False
        todo.append(ver("Una búsqueda con símbolos peligrosos no rompe nada", sigue))

        con = b._leer()
        try:
            con.execute("DELETE FROM fichas")
            escribe = True
        except sqlite3.OperationalError:
            escribe = False
        con.close()
        todo.append(ver("La conexión de la IA no puede escribir", not escribe and b.estado()["fichas"] == 4))

        _exportado(tmp, "dossier", [f("dossier:case-zeus", "ZeuS", "Malware bancario con webinjects, P2P y DGA"),
                                    f("dossier:case-mirai", "Mirai", "Botnet IoT")])
        _exportado(tmp, "mitre", [f("mitre:enterprise:T1566", "T1566 Phishing", "Adversaries may send phishing messages")])
        r = b.revisar()
        cuenta = {a["artefacto"]: (a["nuevas"], a["cambiadas"], a["eliminadas"]) for a in r["resumen"]}
        todo.append(ver("La revisión ve nuevas, cambiadas y eliminadas",
                        cuenta["dossier"] == (1, 1, 0) and cuenta["mitre"] == (0, 0, 1)))
        b.importar(r["senal"])
        todo.append(ver("Importar aplica los cambios", b.estado()["fichas"] == 4 and
                        "DGA" in b.buscar("ZeuS")[0]["texto"] and not b.buscar("SolarWinds")))

        _exportado(tmp, "libro_cves", [f("libro:CVE-2024-3400", "CVE", "Texto cambiado a mano")], cambiar_huella=True)
        r = b.revisar()
        todo.append(ver("Un archivo cambiado a mano se rechaza", any("huella" in x for x in r["errores"])))
        _exportado(tmp, "libro_cves", [f("dossier:intrusa", "Intrusa", "Se hace pasar por otro artefacto")])
        todo.append(ver("Una ficha no puede colarse en otro artefacto", any("no pertenece" in x for x in b.revisar()["errores"])))
        _exportado(tmp, "libro_cves", [f("libro:CVE-2024-0001", "Invisible", "Hola​‮mundo")])
        b.importar(b.revisar()["senal"])
        todo.append(ver("Se quitan los caracteres invisibles", b.buscar("CVE-2024-0001")[0]["texto"] == "Holamundo"))

        _exportado(tmp, "dossier", [f("dossier:tool-rubeus", "Rubeus", "Herramienta para kerberoasting, técnica T1558.003")])
        _exportado(tmp, "mitre", [
            f("mitre:enterprise:T1558.003", "T1558.003 Kerberoasting", "Grupos G0016 y software S0692\n\n"
              "Adversaries may abuse a valid Kerberos ticket-granting ticket to obtain service tickets"),
            f("mitre:enterprise:G0016", "G0016 APT29", "Grupo ruso\n\nAPT29 is a threat group attributed to Russia"),
        ])
        _exportado(tmp, "tryhackme", [f("thm:sala:kerb", "Kerberoasting", "Mis apuntes. Pedir tickets TGS (T1558.003)")])
        b.importar(b.revisar()["senal"])
        principal = b.buscar("T1558.003", maximo=1)
        cx = b.conexiones(principal)
        claves = [c["clave"] for c in cx["fichas"]]
        todo.append(ver("Las conexiones encuentran tus fichas que citan la técnica",
                        "thm:sala:kerb" in claves or "dossier:tool-rubeus" in claves))
        todo.append(ver("Las conexiones siguen los identificadores citados", "mitre:enterprise:G0016" in claves
                        and "APT29 is a threat group" in next(c["resumen"] for c in cx["fichas"] if c["clave"] == "mitre:enterprise:G0016")))
        todo.append(ver("Una conexión no repite las fichas principales",
                        not set(claves) & {p["clave"] for p in principal}))
        con = b._escribir()
        con.execute("DELETE FROM enlaces")
        con.commit()
        con.close()
        b2 = Biblioteca(Path(tmp) / "b.db", tmp)
        todo.append(ver("Una biblioteca antigua rehace sus enlaces al abrir", b2.conexiones(b2.buscar("T1558.003"))["fichas"]))

        todo.append(ver("Una clave rara no se toma por identificador",
                        _ident_propio("libro:CVE-2021-1; DROP") is None and _ident_propio("libro:CVE-2021-44228") == "CVE-2021-44228"))

    print("Fuentes oficiales del paso 12.1")
    with tempfile.TemporaryDirectory() as tmp:
        todo2 = []
        _exportado(tmp, "mitre", [f("mitre:enterprise:T1558.003", "T1558.003 Kerberoasting", "Adversaries may abuse a valid Kerberos ticket")])
        _exportado(tmp, "dossier", [f("dossier:kerb", "Kerberoasting", "Pedir tickets de servicio y crackearlos. T1558.003")])
        _exportado(tmp, "sigma", [f(f"sigma:r{i}", f"Kerberoasting regla {i}", "Regla Sigma. Técnicas ATT&CK T1558.003") for i in range(5)])
        _exportado(tmp, "atomic", [f("atomic:a1", "T1558.003 · Rubeus kerberoast", "Prueba de laboratorio T1558.003")])
        _exportado(tmp, "cwe", [f("cwe:CWE-79", "CWE-79 Cross-site Scripting", "Improper neutralization. CAPEC-63")])
        _exportado(tmp, "capec", [f("capec:CAPEC-63", "CAPEC-63 Cross-Site Scripting", "Debilidades CWE CWE-79")])
        b = Biblioteca(Path(tmp) / "b.db", tmp)
        b.importar(b.revisar()["senal"])
        con = b._leer()
        propias = dict(con.execute("SELECT clave, propia FROM fichas"))
        con.close()
        todo2.append(ver("Las fuentes nuevas se importan y son oficiales",
                         propias.get("sigma:r0") == 0 and propias.get("cwe:CWE-79") == 0 and propias.get("dossier:kerb") == 1))
        todo2.append(ver("Buscar CWE-79 da su ficha", b.buscar("explícame CWE-79")[0]["clave"] == "cwe:CWE-79"))
        todo2.append(ver("Buscar CAPEC-63 da su ficha", b.buscar("CAPEC-63")[0]["clave"] == "capec:CAPEC-63"))
        encontradas = b.buscar("kerberoasting regla")
        todo2.append(ver("Como mucho una regla Sigma entre los resultados",
                         sum(x["artefacto"] == "sigma" for x in encontradas) <= 1))
        encontradas = b.buscar("T1558.003")
        enl = b.conexiones(encontradas)
        fuentes = [x["clave"].split(":")[0] for x in encontradas + enl["fichas"]]
        todo2.append(ver("Una técnica trae su ficha de MITRE, la tuya, una regla Sigma y una prueba de Atomic",
                         fuentes[0] == "mitre" and "dossier" in fuentes and fuentes.count("sigma") == 1 and "atomic" in fuentes))
        encontradas = b.buscar("CWE-79")
        enl = b.conexiones(encontradas)
        todo2.append(ver("Una debilidad trae su patrón CAPEC",
                         any(x["clave"] == "capec:CAPEC-63" for x in encontradas + enl["fichas"])))
        todo2.append(ver("Un identificador nuevo con forma rara no define nada", _ident_propio("cwe:CWE-79; DROP") is None))
        todo.extend(todo2)

    print("Paso 12.7")
    with tempfile.TemporaryDirectory() as tmp:
        _exportado(tmp, "mitre", [
            f("mitre:enterprise:G0020", "G0020 Equation", "Equation is a sophisticated threat group. Técnicas T1120"),
            f("mitre:enterprise:G1002", "G1002 BITTER", "BITTER has executed OLE objects using Microsoft Equation Editor"),
            f("mitre:enterprise:G0080", "G0080 Cobalt Group", "Cobalt Group has used Microsoft Equation Editor exploits"),
        ])
        b = Biblioteca(Path(tmp) / "b.db", tmp)
        b.importar(b.revisar()["senal"])
        claves = [x["clave"] for x in b.buscar("Equation")]
        todo.append(ver("Un grupo nombrado en el título deja fuera a los que solo lo citan en el texto",
                        claves == ["mitre:enterprise:G0020"]))
        claves = [x["clave"] for x in b.buscar("G0020 Equation puedes buscar mas información de este grupo por internet")]
        todo.append(ver("Con el identificador encontrado, su nombre y las palabras vacías no traen ruido",
                        claves == ["mitre:enterprise:G0020"]))
        claves = [x["clave"] for x in b.buscar("Equation Editor")]
        todo.append(ver("Si ningún grupo lleva la palabra en el título, se encuentran por el texto",
                        "mitre:enterprise:G1002" in claves))

        print("Resultado", "TODO OK" if all(todo) else "HAY FALLOS")
