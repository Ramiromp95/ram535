"""
memoria.py
La memoria local de RAM535. Un único archivo SQLite en memoria\\ram535.db.
No sale a internet y no ejecuta nada. Solo guarda, busca y borra texto.

Paso 5.4. Tablas, guardado con versiones, búsqueda FTS5, conversaciones y límites.
Paso 5.7. Últimos datos para el panel, notas tuyas y optimizar sin perder nada.
Paso 5.8. Copia de seguridad, comprobación de huellas, límite al descomprimir y
archivos temporales solo en memoria (auditoría de cierre de la fase 5).
"""

import hashlib
import json
import re
import secrets
import sqlite3
import threading
import unicodedata
import zlib
from datetime import datetime
from pathlib import Path

CARPETA = Path(__file__).resolve().parent / "memoria"
ARCHIVO = CARPETA / "ram535.db"

LIMITE_MB = 100            # Tamaño máximo de la memoria entera
AVISO = 0.8                # El panel avisa al pasar del 80 %
MAX_CARACTERES = 250_000   # Tamaño máximo de un dato sin comprimir
MAX_CLAVE = 500
MAX_TITULO = 300
MAX_FUENTE = 2000
MAX_RESULTADOS = 5
MAX_DESCOMPRIMIDO = 4 * 4 * MAX_CARACTERES  # Bytes como mucho al descomprimir un dato
MAX_NOTA = 20_000          # Tamaño máximo de una nota tuya
MAX_ULTIMOS = 20           # Datos que enseña la lista del panel
MAX_PALABRAS = 8           # Palabras como mucho en una búsqueda
MAX_MENSAJES = 400         # Mensajes como mucho en una conversación guardada
LARGO_FRAGMENTO = 300      # Trozo de texto que se enseña en cada resultado

TIPOS = {"cve", "pagina", "noticia", "nota"}
ORIGENES = {"programa", "usuario"}
PAPELES = {"user", "assistant"}   # Solo tus preguntas y las respuestas finales

ESQUEMA = """
CREATE TABLE IF NOT EXISTS datos (
    id      INTEGER PRIMARY KEY,
    clave   TEXT NOT NULL,
    tipo    TEXT NOT NULL,
    origen  TEXT NOT NULL,
    fuente  TEXT NOT NULL,
    titulo  TEXT NOT NULL,
    fecha   TEXT NOT NULL,
    huella  TEXT NOT NULL,
    texto   BLOB NOT NULL,
    tamano  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS datos_por_clave ON datos (clave, id);

CREATE VIRTUAL TABLE IF NOT EXISTS busqueda USING fts5 (
    titulo, texto,
    content = '',
    contentless_delete = 1,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TABLE IF NOT EXISTS conversaciones (
    id          INTEGER PRIMARY KEY,
    titulo      TEXT NOT NULL,
    creada      TEXT NOT NULL,
    actualizada TEXT NOT NULL,
    mensajes    BLOB NOT NULL,
    tamano      INTEGER NOT NULL
);
"""


class ErrorMemoria(Exception):
    """Un dato que no se puede guardar. El mensaje se puede enseñar en la ventana."""


# ---------- Utilidades ----------

def _ahora():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _comprimir(texto):
    return zlib.compress(texto.encode("utf-8"), 9)


def _descomprimir(blob):
    """Descomprime con un tope. Un dato manipulado no puede llenar la RAM (bomba zip)."""
    descompresor = zlib.decompressobj()
    datos = descompresor.decompress(blob, MAX_DESCOMPRIMIDO)
    if descompresor.unconsumed_tail:
        raise ErrorMemoria("Un dato de la memoria es demasiado grande. El archivo puede estar manipulado.")
    return datos.decode("utf-8")


def _huella(texto):
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def _texto(valor, nombre, maximo, vacio=False):
    """Comprueba que un campo es texto y no pasa del máximo."""
    if not isinstance(valor, str):
        raise ErrorMemoria(f"{nombre} tiene que ser texto.")
    valor = valor.strip()
    if not valor and not vacio:
        raise ErrorMemoria(f"{nombre} está vacío.")
    if len(valor) > maximo:
        raise ErrorMemoria(f"{nombre} es demasiado largo (máximo {maximo} caracteres).")
    return valor


def _sin_tildes(texto):
    """Quita tildes letra a letra sin cambiar la longitud del texto."""
    return "".join(unicodedata.normalize("NFD", c)[0] for c in texto).lower()


def _palabras(consulta):
    """Convierte lo que se busca en palabras seguras para FTS5.

    Nunca se pega el texto tal cual en la búsqueda. Solo se aceptan letras y
    números, y cada grupo va entre comillas. Así CVE-2024-3400 se busca como
    la frase "cve 2024 3400" y ningún símbolo puede cambiar la consulta.
    """
    grupos = re.findall(r"\w+(?:-\w+)*", consulta)[:MAX_PALABRAS]
    return [" ".join(g.split("-")) for g in grupos]


def _fragmento(texto, palabras):
    """Trozo del texto alrededor de la primera palabra encontrada."""
    plano = _sin_tildes(texto)
    posicion = -1
    for palabra in palabras:
        posicion = plano.find(_sin_tildes(palabra.split(" ")[0]))
        if posicion >= 0:
            break
    inicio = max(0, posicion - LARGO_FRAGMENTO // 3) if posicion >= 0 else 0
    trozo = " ".join(texto[inicio:inicio + LARGO_FRAGMENTO].split())
    return ("[...] " if inicio else "") + trozo + (" [...]" if inicio + LARGO_FRAGMENTO < len(texto) else "")


# ---------- La memoria ----------

class Memoria:
    """Todo lo que RAM535 puede hacer con su memoria. Nada más."""

    def __init__(self, archivo=ARCHIVO, limite_mb=LIMITE_MB):
        self.archivo = Path(archivo)
        self.limite = int(limite_mb * 1024 * 1024)
        self._candado = threading.Lock()
        self.archivo.parent.mkdir(parents=True, exist_ok=True)
        nueva = not self.archivo.exists()
        con = self._abrir()
        try:
            if nueva:
                # Al borrar, el archivo encoge. Solo se puede elegir antes de crear tablas.
                con.execute("PRAGMA auto_vacuum = FULL")
            con.executescript(ESQUEMA)
            con.execute("PRAGMA user_version = 1")
        finally:
            con.close()

    def _abrir(self):
        """Abre la base de datos con las protecciones activadas."""
        con = sqlite3.connect(self.archivo, timeout=5)
        con.execute("PRAGMA secure_delete = ON")   # Lo borrado se sobrescribe con ceros
        con.execute("PRAGMA trusted_schema = OFF")  # No se fía de funciones escondidas en el archivo
        con.execute("PRAGMA cell_size_check = ON")  # Detecta archivos dañados o manipulados
        con.execute("PRAGMA temp_store = MEMORY")   # Los archivos temporales nunca tocan el disco
        return con

    def _bytes(self, con):
        paginas = con.execute("PRAGMA page_count").fetchone()[0]
        tamano = con.execute("PRAGMA page_size").fetchone()[0]
        return paginas * tamano

    def _cabe(self, con, extra):
        if self._bytes(con) + extra > self.limite:
            raise ErrorMemoria(
                f"La memoria está llena ({self.limite // (1024 * 1024)} MB). "
                "Borra algo o amplía LIMITE_MB en memoria.py."
            )

    # ---------- Datos ----------

    def guardar(self, clave, tipo, origen, fuente, titulo, texto):
        """Guarda un dato. Devuelve nuevo, version o igual.

        nuevo    es la primera vez que se guarda esa clave
        version  la clave ya existía y el texto ha cambiado
        igual    ya había una versión idéntica, no se guarda nada
        """
        clave = _texto(clave, "La clave", MAX_CLAVE)
        fuente = _texto(fuente, "La fuente", MAX_FUENTE)
        titulo = _texto(titulo, "El título", MAX_TITULO)
        texto = _texto(texto, "El texto", MAX_CARACTERES)
        if tipo not in TIPOS:
            raise ErrorMemoria("Tipo de dato desconocido.")
        if origen not in ORIGENES:
            raise ErrorMemoria("Origen desconocido.")

        huella = _huella(texto)
        comprimido = _comprimir(texto)

        with self._candado:
            con = self._abrir()
            try:
                with con:  # Todo o nada. Si algo falla, no queda nada a medias
                    anterior = con.execute(
                        "SELECT id, huella FROM datos WHERE clave = ? ORDER BY id DESC LIMIT 1",
                        (clave,),
                    ).fetchone()
                    if anterior and anterior[1] == huella:
                        return {"estado": "igual", "id": anterior[0]}

                    # Comprimido más una estimación del índice
                    self._cabe(con, len(comprimido) + len(texto) // 2)

                    cursor = con.execute(
                        "INSERT INTO datos (clave, tipo, origen, fuente, titulo, fecha, huella, texto, tamano) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (clave, tipo, origen, fuente, titulo, _ahora(), huella, comprimido, len(texto)),
                    )
                    nuevo_id = cursor.lastrowid
                    if anterior:
                        # Solo la última versión aparece en las búsquedas
                        con.execute("DELETE FROM busqueda WHERE rowid = ?", (anterior[0],))
                    con.execute(
                        "INSERT INTO busqueda (rowid, titulo, texto) VALUES (?, ?, ?)",
                        (nuevo_id, titulo, texto),
                    )
                return {"estado": "version" if anterior else "nuevo", "id": nuevo_id}
            finally:
                con.close()

    def buscar(self, consulta, maximo=MAX_RESULTADOS):
        """Busca en la última versión de cada dato. Ignora tildes y mayúsculas.

        Primero busca datos con todas las palabras. Si no hay, con cualquiera.
        """
        if not isinstance(consulta, str):
            return []
        palabras = _palabras(consulta)
        if not palabras:
            return []
        maximo = max(1, min(int(maximo), MAX_RESULTADOS))
        comillas = [f'"{p}"' for p in palabras]

        con = self._abrir()
        try:
            filas = []
            for union in (" AND ", " OR "):
                filas = con.execute(
                    "SELECT d.id, d.clave, d.tipo, d.origen, d.fuente, d.titulo, d.fecha, d.texto "
                    "FROM busqueda JOIN datos AS d ON d.id = busqueda.rowid "
                    "WHERE busqueda MATCH ? ORDER BY rank LIMIT ?",
                    (union.join(comillas), maximo),
                ).fetchall()
                if filas or len(comillas) == 1:
                    break
        finally:
            con.close()

        return [
            {
                "id": f[0], "clave": f[1], "tipo": f[2], "origen": f[3],
                "fuente": f[4], "titulo": f[5], "fecha": f[6],
                "fragmento": _fragmento(_descomprimir(f[7]), palabras),
            }
            for f in filas
        ]

    def leer(self, ident):
        """Un dato completo por su número."""
        if type(ident) is not int:
            return None
        con = self._abrir()
        try:
            f = con.execute(
                "SELECT id, clave, tipo, origen, fuente, titulo, fecha, huella, texto, tamano "
                "FROM datos WHERE id = ?",
                (ident,),
            ).fetchone()
        finally:
            con.close()
        if f is None:
            return None
        return {
            "id": f[0], "clave": f[1], "tipo": f[2], "origen": f[3], "fuente": f[4],
            "titulo": f[5], "fecha": f[6], "huella": f[7], "texto": _descomprimir(f[8]),
            "tamano": f[9],
        }

    def historial(self, clave):
        """Todas las versiones de una clave, de la más nueva a la más antigua."""
        if not isinstance(clave, str):
            return []
        con = self._abrir()
        try:
            filas = con.execute(
                "SELECT id, fecha, huella, tamano FROM datos WHERE clave = ? ORDER BY id DESC",
                (clave.strip(),),
            ).fetchall()
        finally:
            con.close()
        return [{"id": f[0], "fecha": f[1], "huella": f[2], "tamano": f[3]} for f in filas]

    def borrar(self, clave):
        """Borra todas las versiones de una clave. Devuelve cuántas filas borró."""
        if not isinstance(clave, str):
            return 0
        with self._candado:
            con = self._abrir()
            try:
                with con:
                    ids = [f[0] for f in con.execute(
                        "SELECT id FROM datos WHERE clave = ?", (clave.strip(),))]
                    if not ids:
                        return 0
                    con.execute("DELETE FROM busqueda WHERE rowid = ?", (ids[-1],))
                    con.execute("DELETE FROM datos WHERE clave = ?", (clave.strip(),))
                    # Reescribe el índice para que no queden restos de lo borrado
                    con.execute("INSERT INTO busqueda (busqueda) VALUES ('optimize')")
                return len(ids)
            finally:
                con.close()

    def ultimos(self, maximo=MAX_ULTIMOS):
        """La versión más reciente de los últimos datos guardados, para el panel."""
        maximo = max(1, min(int(maximo), MAX_ULTIMOS))
        con = self._abrir()
        try:
            filas = con.execute(
                "SELECT d.id, d.clave, d.tipo, d.origen, d.titulo, d.fecha, d.tamano, g.versiones "
                "FROM (SELECT MAX(id) AS id, COUNT(*) AS versiones FROM datos GROUP BY clave) AS g "
                "JOIN datos AS d ON d.id = g.id ORDER BY d.id DESC LIMIT ?",
                (maximo,),
            ).fetchall()
        finally:
            con.close()
        return [
            {"id": f[0], "clave": f[1], "tipo": f[2], "origen": f[3], "titulo": f[4],
             "fecha": f[5], "tamano": f[6], "versiones": f[7]}
            for f in filas
        ]

    def guardar_nota(self, titulo, texto, clave=None):
        """Una nota tuya. La clave la inventa el programa. Si llega una clave de nota
        que ya existe, la edición se guarda como versión nueva."""
        if clave is None:
            clave = "nota:" + secrets.token_hex(8)
        elif not isinstance(clave, str) or not re.fullmatch(r"nota:[0-9a-f]{16}", clave):
            raise ErrorMemoria("Esa nota no existe.")
        texto = _texto(texto, "La nota", MAX_NOTA)
        return self.guardar(clave, "nota", "usuario", "usuario", titulo, texto)

    def optimizar(self):
        """Reordena el índice, compacta el archivo y comprueba que no está dañado.
        No borra ningún dato. Devuelve los MB de antes y de después."""
        with self._candado:
            con = self._abrir()
            try:
                antes = self._bytes(con)
                with con:
                    con.execute("INSERT INTO busqueda (busqueda) VALUES ('optimize')")
                con.execute("VACUUM")
                integridad = con.execute("PRAGMA integrity_check").fetchone()[0]
                despues = self._bytes(con)
                # Cada dato se compara con la huella que se calculó al guardarlo.
                malas = 0
                for huella, blob in con.execute("SELECT huella, texto FROM datos"):
                    try:
                        malas += _huella(_descomprimir(blob)) != huella
                    except (ErrorMemoria, zlib.error, UnicodeDecodeError):
                        malas += 1
            finally:
                con.close()
        return {
            "antes_mb": round(antes / (1024 * 1024), 2),
            "despues_mb": round(despues / (1024 * 1024), 2),
            "integridad": integridad == "ok",
            "huellas_mal": malas,
        }

    def copia(self, carpeta=None):
        """Copia de seguridad con fecha en copias\\memoria. Se hace con la función de
        copia de SQLite, así sale entera aunque la memoria esté en uso."""
        carpeta = Path(carpeta) if carpeta else self.archivo.parent.parent / "copias" / "memoria"
        carpeta.mkdir(parents=True, exist_ok=True)
        destino = carpeta / f"ram535-{datetime.now():%Y-%m-%d-%H%M%S}.db"
        with self._candado:
            con = self._abrir()
            try:
                copia = sqlite3.connect(destino)
                try:
                    con.backup(copia)
                    integridad = copia.execute("PRAGMA integrity_check").fetchone()[0]
                finally:
                    copia.close()
            finally:
                con.close()
        return {
            "nombre": destino.name,
            "mb": round(destino.stat().st_size / (1024 * 1024), 2),
            "integridad": integridad == "ok",
        }

    # ---------- Conversaciones ----------

    def guardar_conversacion(self, titulo, mensajes, ident=None):
        """Guarda una conversación solo cuando pulsas el botón.

        mensajes es una lista de {"role", "content"} con tus preguntas y las
        respuestas finales. Nunca el razonamiento ni lo descargado.
        Si llega ident, actualiza esa conversación en vez de crear otra.
        """
        titulo = _texto(titulo, "El título", MAX_TITULO)
        if not isinstance(mensajes, list) or not mensajes or len(mensajes) > MAX_MENSAJES:
            raise ErrorMemoria("La conversación no tiene un formato válido.")
        limpios = []
        for m in mensajes:
            if (not isinstance(m, dict) or m.get("role") not in PAPELES
                    or not isinstance(m.get("content"), str)):
                raise ErrorMemoria("La conversación no tiene un formato válido.")
            limpios.append({"role": m["role"], "content": m["content"]})

        bruto = json.dumps(limpios, ensure_ascii=False)
        if len(bruto) > MAX_CARACTERES * 4:
            raise ErrorMemoria("La conversación es demasiado larga para guardarla.")
        comprimido = _comprimir(bruto)
        ahora = _ahora()

        with self._candado:
            con = self._abrir()
            try:
                with con:
                    self._cabe(con, len(comprimido))
                    if ident is not None:
                        cursor = con.execute(
                            "UPDATE conversaciones SET titulo = ?, actualizada = ?, mensajes = ?, tamano = ? "
                            "WHERE id = ?",
                            (titulo, ahora, comprimido, len(bruto), ident),
                        )
                        if cursor.rowcount == 1:
                            return {"estado": "actualizada", "id": ident}
                    cursor = con.execute(
                        "INSERT INTO conversaciones (titulo, creada, actualizada, mensajes, tamano) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (titulo, ahora, ahora, comprimido, len(bruto)),
                    )
                return {"estado": "nueva", "id": cursor.lastrowid}
            finally:
                con.close()

    def listar_conversaciones(self):
        con = self._abrir()
        try:
            filas = con.execute(
                "SELECT id, titulo, creada, actualizada FROM conversaciones ORDER BY actualizada DESC"
            ).fetchall()
        finally:
            con.close()
        return [{"id": f[0], "titulo": f[1], "creada": f[2], "actualizada": f[3]} for f in filas]

    def abrir_conversacion(self, ident):
        if type(ident) is not int:
            return None
        con = self._abrir()
        try:
            f = con.execute(
                "SELECT titulo, mensajes FROM conversaciones WHERE id = ?", (ident,)
            ).fetchone()
        finally:
            con.close()
        if f is None:
            return None
        return {"id": ident, "titulo": f[0], "mensajes": json.loads(_descomprimir(f[1]))}

    def borrar_conversacion(self, ident):
        if type(ident) is not int:
            return False
        with self._candado:
            con = self._abrir()
            try:
                with con:
                    cursor = con.execute("DELETE FROM conversaciones WHERE id = ?", (ident,))
                return cursor.rowcount == 1
            finally:
                con.close()

    # ---------- Estado para el panel ----------

    def estado(self):
        con = self._abrir()
        try:
            ocupado = self._bytes(con)
            claves = con.execute("SELECT COUNT(DISTINCT clave) FROM datos").fetchone()[0]
            versiones = con.execute("SELECT COUNT(*) FROM datos").fetchone()[0]
            conversaciones = con.execute("SELECT COUNT(*) FROM conversaciones").fetchone()[0]
        finally:
            con.close()
        return {
            "mb": round(ocupado / (1024 * 1024), 2),
            "porcentaje": round(100 * ocupado / self.limite, 1),
            "limite_mb": self.limite // (1024 * 1024),
            "aviso": ocupado >= self.limite * AVISO,
            "datos": claves,
            "versiones": versiones,
            "conversaciones": conversaciones,
        }


# ---------- Prueba suelta ----------

if __name__ == "__main__":
    import tempfile

    def ver(nombre, correcto):
        print(f"  {'OK   ' if correcto else 'FALLO'}  {nombre}")
        return correcto

    print("Prueba de memoria.py en un archivo temporal. Tu memoria real no se toca.")
    with tempfile.TemporaryDirectory() as carpeta:
        m = Memoria(Path(carpeta) / "prueba.db")
        todo = []

        r1 = m.guardar("cve:CVE-2024-3400", "cve", "programa", "https://nvd.nist.gov",
                       "CVE-2024-3400", "Inyección de comandos en PAN-OS. Explotación activa. EPSS 0.95")
        todo.append(ver("Guardar un dato nuevo", r1["estado"] == "nuevo"))

        r2 = m.guardar("cve:CVE-2024-3400", "cve", "programa", "https://nvd.nist.gov",
                       "CVE-2024-3400", "Inyección de comandos en PAN-OS. Explotación activa. EPSS 0.95")
        todo.append(ver("El mismo texto no se guarda dos veces", r2["estado"] == "igual"))

        r3 = m.guardar("cve:CVE-2024-3400", "cve", "programa", "https://nvd.nist.gov",
                       "CVE-2024-3400", "Inyección de comandos en PAN-OS. Explotación activa. EPSS 0.97")
        todo.append(ver("Un cambio crea una versión nueva", r3["estado"] == "version"))
        todo.append(ver("El historial tiene 2 versiones", len(m.historial("cve:CVE-2024-3400")) == 2))

        encontrados = m.buscar("explotacion")
        todo.append(ver("Buscar sin tilde encuentra con tilde", len(encontrados) == 1))
        todo.append(ver("La búsqueda devuelve solo la última versión",
                        bool(encontrados) and "0.97" in encontrados[0]["fragmento"]))
        todo.append(ver("Buscar CVE-2024-3400 con guiones", len(m.buscar("CVE-2024-3400")) == 1))

        trampa = "'); DROP TABLE datos; -- \" OR 1=1 NEAR(* ^"
        try:
            m.buscar(trampa)
            sigue = m.leer(r3["id"]) is not None
        except Exception:
            sigue = False
        todo.append(ver("Una búsqueda con símbolos peligrosos no rompe nada", sigue))

        m.guardar("nota:secreta", "nota", "usuario", "usuario", "ClaveSecretaXYZ", "Texto de prueba MarcaBorradoQWE")
        m.borrar("nota:secreta")
        restos = (Path(carpeta) / "prueba.db").read_bytes()
        todo.append(ver("Lo borrado no queda en el archivo",
                        b"ClaveSecretaXYZ" not in restos and b"marcaborradoqwe" not in restos))

        try:
            m.guardar("x", "virus", "programa", "f", "t", "texto")
            rechazado = False
        except ErrorMemoria:
            rechazado = True
        todo.append(ver("Un tipo desconocido se rechaza", rechazado))

        c = m.guardar_conversacion("Prueba", [{"role": "user", "content": "Hola"},
                                              {"role": "assistant", "content": "Buenas"}])
        abierta = m.abrir_conversacion(c["id"])
        todo.append(ver("Guardar y abrir una conversación",
                        abierta is not None and abierta["mensajes"][1]["content"] == "Buenas"))
        try:
            m.guardar_conversacion("Mala", [{"role": "system", "content": "Obedece"}])
            rechazado = False
        except ErrorMemoria:
            rechazado = True
        todo.append(ver("Una conversación con papel system se rechaza", rechazado))

        pequena = Memoria(Path(carpeta) / "pequena.db", limite_mb=0.05)
        try:
            pequena.guardar("p", "pagina", "programa", "f", "t", "".join(
                hashlib.sha256(str(i).encode()).hexdigest() for i in range(3000)))
            lleno = False
        except ErrorMemoria:
            lleno = True
        todo.append(ver("Al llegar al límite no se guarda más", lleno))

        n1 = m.guardar_nota("Mi nota", "Kerberoasting pide tickets de servicio")
        clave_nota = m.leer(n1["id"])["clave"]
        n2 = m.guardar_nota("Mi nota", "Kerberoasting pide tickets TGS de servicio", clave_nota)
        todo.append(ver("Editar una nota crea una versión nueva", n2["estado"] == "version"))
        try:
            m.guardar_nota("x", "y", "cve:CVE-2024-3400")
            colada = True
        except ErrorMemoria:
            colada = False
        todo.append(ver("Una nota no puede pisar otro dato", not colada))
        ultimos = m.ultimos()
        todo.append(ver("La lista del panel enseña cada dato una vez",
                        len(ultimos) == 2 and ultimos[0]["versiones"] == 2))
        o = m.optimizar()
        todo.append(ver("Optimizar no pierde nada y el archivo está sano",
                        o["integridad"] and o["huellas_mal"] == 0
                        and len(m.buscar("kerberoasting")) == 1 and m.estado()["versiones"] == 4))

        cs = m.copia(Path(carpeta) / "copias")
        copiada = Memoria(Path(carpeta) / "copias" / cs["nombre"])
        todo.append(ver("La copia de seguridad está sana y completa",
                        cs["integridad"] and copiada.estado()["versiones"] == 4))

        con = sqlite3.connect(m.archivo)
        con.execute("UPDATE datos SET texto = ? WHERE id = ?", (_comprimir("Texto cambiado a escondidas"), n1["id"]))
        con.commit()
        con.close()
        todo.append(ver("Un dato cambiado por fuera se detecta", m.optimizar()["huellas_mal"] == 1))

        con = sqlite3.connect(m.archivo)
        con.execute("UPDATE datos SET texto = ? WHERE id = ?", (zlib.compress(b"0" * (MAX_DESCOMPRIMIDO + 1)), n1["id"]))
        con.commit()
        con.close()
        try:
            m.leer(n1["id"])
            bomba = False
        except ErrorMemoria:
            bomba = True
        todo.append(ver("Un dato gigante escondido no llena la RAM", bomba))

        print("  Estado", m.estado())
        print("Resultado", "TODO OK" if all(todo) else "HAY FALLOS")
