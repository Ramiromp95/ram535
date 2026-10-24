import base64
import hashlib
import json
import os
import sys
import threading
import traceback
import urllib.error
from collections import OrderedDict
from pathlib import Path

# Ajuste 11.4. Abierto con el acceso directo (pythonw) no hay terminal. Lo que se escribiría
# en ella, como la versión al arrancar o los errores, va a registro\ram535.log.
if sys.stdout is None or sys.stderr is None:
    (Path(__file__).parent / "registro").mkdir(exist_ok=True)
    _salida = open(Path(__file__).parent / "registro" / "ram535.log", "a", encoding="utf-8", buffering=1)
    sys.stdout = sys.stdout or _salida
    sys.stderr = sys.stderr or _salida

os.environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
    "--proxy-server=http://127.0.0.1:9 "
    "--disable-background-networking "
    "--disable-component-update "
    "--disable-domain-reliability "
    "--disable-sync "
    "--no-pings "
    "--disable-features=msSmartScreenProtection"
)

import webview

import biblioteca
import herramientas
import memoria
import panel
import red
from cerebro import Cerebro

VERSION = "12.9"  # Se muestra en la terminal al arrancar, para saber qué versión está abierta
LIMITE_PREGUNTA = 8000
ESPERA_PERMISO = 600  # segundos. Si no contestas, se rechaza.
MAX_LECTURAS_GUARDABLES = 50  # Lecturas de esta sesión que aún se pueden guardar
LARGO_TITULO = 80  # Caracteres de tu primera pregunta que forman el título


class Puente:
    """Lo único que la ventana puede pedirle a Python."""

    def __init__(self):
        self._cerebro = Cerebro()
        self._ocupado = threading.Lock()
        self._ventana = None
        self._candado_permiso = threading.Lock()
        self._permiso = None
        self._contador = 0
        self._panel = panel.Panel()
        # Lo que se puede guardar vive aquí, en Python. La ventana solo conoce un número.
        self._guardables = OrderedDict()
        self._candado_memoria = threading.Lock()
        self._contador_lecturas = 0
        self._conversacion_id = None  # Número de la conversación guardada que estás siguiendo
        try:
            self._memoria = memoria.Memoria()
            herramientas.memoria_local = self._memoria  # La IA consulta la misma memoria
        except Exception:
            traceback.print_exc()
            self._memoria = None
        # La señal de la última revisión vive en Python. La ventana no la conoce.
        self._senal_biblioteca = None
        try:
            self._biblioteca = biblioteca.Biblioteca()
            herramientas.biblioteca_local = self._biblioteca  # La IA consulta la misma biblioteca
        except Exception:
            traceback.print_exc()
            self._biblioteca = None

    def _enviar(self, funcion, dato):
        self._ventana.run_js(f"{funcion}({json.dumps(dato)})")

    # ---------- Panel de seguridad ----------

    def _avisar_panel(self, datos):
        """Manda datos al panel. Si la ventana aún no lo tiene, no pasa nada."""
        if self._ventana is None:
            return
        try:
            self._ventana.run_js(f"if (ram.panel) ram.panel({json.dumps(datos)})")
        except Exception:
            traceback.print_exc()

    def _al_registrar(self):
        """red.py lo llama tras anotar cada conexión o cada alta en la lista blanca.
        Ajuste 7.3. La lista blanca ya no se envía a la ventana. Vive solo en lista_blanca.txt."""
        self._avisar_panel({"conexiones": self._panel.conexiones()})

    def _revisar_exposicion(self):
        """Comprueba Ollama en segundo plano para no retrasar la respuesta."""
        hilo = threading.Thread(
            target=lambda: self._avisar_panel({"exposicion": panel.exposicion()}),
            daemon=True,
        )
        hilo.start()

    def estado_panel(self):
        """La ventana pide todos los datos del panel al arrancar."""
        datos = self._panel.todo()
        datos["conversaciones"] = self._lista_conversaciones()
        datos["memoria"] = self._datos_memoria()
        datos["biblioteca"] = self._estado_biblioteca()
        return datos

    def _pedir_permiso(self, peticion):
        """Muestra la tarjeta en la ventana y espera a que el usuario decida.
        Devuelve True, False o "sitio" (aprobar el sitio durante esta pregunta)."""
        with self._candado_permiso:
            self._contador += 1
            ident = self._contador
            if not peticion.get("automatico"):
                pendiente = {"id": ident, "evento": threading.Event(), "aprobado": False}
                self._permiso = pendiente

        # cerebro.py ya decidió que este sitio estaba aprobado. Solo se muestra la tarjeta.
        if peticion.get("automatico"):
            self._enviar("ram.pedirPermiso", {"id": ident, **peticion})
            return True

        self._enviar("ram.pedirPermiso", {"id": pendiente["id"], **peticion})
        pendiente["evento"].wait(ESPERA_PERMISO)

        with self._candado_permiso:
            self._permiso = None
            decidido = pendiente["evento"].is_set()
        if not decidido:
            self._enviar("ram.caducar", pendiente["id"])
            return False
        return pendiente["aprobado"]

    def _pedir_alta(self, peticion):
        """Tarjeta de bloqueo. Sitio fuera de la lista blanca. Espera la decisión del usuario.
        Devuelve "ruta", "sitio", "pregunta" o "no"."""
        opciones = {"sitio", "pregunta", "no"} | ({"ruta"} if peticion.get("linea_ruta") else set())
        with self._candado_permiso:
            self._contador += 1
            pendiente = {"id": self._contador, "evento": threading.Event(), "aprobado": "no", "opciones": opciones}
            self._permiso = pendiente

        self._enviar("ram.pedirAlta", {"id": pendiente["id"], **peticion})
        pendiente["evento"].wait(ESPERA_PERMISO)

        with self._candado_permiso:
            self._permiso = None
            decidido = pendiente["evento"].is_set()
        if not decidido:
            self._enviar("ram.caducar", pendiente["id"])
            return "no"
        return pendiente["aprobado"]

    def _usar(self, uso):
        """Muestra la lectura. Si se puede guardar, Python se queda los datos
        y la ventana recibe solo el número de la lectura."""
        datos = uso.pop("memoria", None)
        if datos and uso.get("ok") and self._memoria is not None:
            with self._candado_memoria:
                self._contador_lecturas += 1
                self._guardables[self._contador_lecturas] = datos
                while len(self._guardables) > MAX_LECTURAS_GUARDABLES:
                    self._guardables.popitem(last=False)
                uso["guardable"] = self._contador_lecturas
        self._enviar("ram.usar", uso)

    # ---------- Memoria ----------

    def guardar_lectura(self, ident):
        """Botón «Guardar en memoria». La ventana manda solo el número de la lectura.
        Lo que se guarda es lo que dio el programa, nunca algo que venga de la ventana."""
        if type(ident) is not int:
            return {"ok": False, "error": "Petición incorrecta."}
        if self._memoria is None:
            return {"ok": False, "error": "La memoria no se pudo abrir. Mira la terminal."}
        with self._candado_memoria:
            datos = self._guardables.pop(ident, None)
        if datos is None:
            return {"ok": False, "error": "Esta lectura ya no se puede guardar."}

        cuenta = {"nuevo": 0, "version": 0, "igual": 0}
        for dato in datos:
            try:
                resultado = self._memoria.guardar(origen="programa", **dato)
                cuenta[resultado["estado"]] += 1
            except memoria.ErrorMemoria as error:
                if not any(cuenta.values()):
                    # No se guardó nada. Se devuelve para poder intentarlo otra vez.
                    with self._candado_memoria:
                        self._guardables[ident] = datos
                return {"ok": False, "error": str(error), "nuevos": cuenta["nuevo"],
                        "versiones": cuenta["version"], "iguales": cuenta["igual"]}
            except Exception:
                traceback.print_exc()
                return {"ok": False, "error": "No se pudo guardar. Mira la terminal."}
        self._avisar_panel({"memoria": self._datos_memoria()})
        return {"ok": True, "nuevos": cuenta["nuevo"], "versiones": cuenta["version"],
                "iguales": cuenta["igual"]}

    # ---------- Sección Memoria del panel ----------

    def _datos_memoria(self):
        """Uso de la memoria y últimos datos guardados. None si la memoria no se abrió."""
        if self._memoria is None:
            return None
        try:
            return {"estado": self._memoria.estado(), "ultimos": self._memoria.ultimos()}
        except Exception:
            traceback.print_exc()
            return None

    def borrar_dato(self, ident):
        """Borra un dato y todas sus versiones. La ventana manda el número, nunca la clave."""
        if type(ident) is not int or self._memoria is None:
            return {"ok": False, "error": "Petición incorrecta."}
        try:
            dato = self._memoria.leer(ident)
            if dato is None:
                return {"ok": False, "error": "Ese dato ya no existe.", "memoria": self._datos_memoria()}
            self._memoria.borrar(dato["clave"])
        except Exception:
            traceback.print_exc()
            return {"ok": False, "error": "No se pudo borrar. Mira la terminal."}
        return {"ok": True, "memoria": self._datos_memoria()}

    def leer_nota(self, ident):
        """Devuelve una nota tuya para editarla. Solo notas, nunca otros datos."""
        if type(ident) is not int or self._memoria is None:
            return {"ok": False, "error": "Petición incorrecta."}
        dato = self._memoria.leer(ident)
        if dato is None or dato["tipo"] != "nota" or dato["origen"] != "usuario":
            return {"ok": False, "error": "Esa nota no existe."}
        return {"ok": True, "id": dato["id"], "titulo": dato["titulo"], "texto": dato["texto"]}

    def guardar_nota(self, titulo, texto, ident=None):
        """Guarda una nota nueva o, si llega ident, una versión nueva de esa nota."""
        if self._memoria is None:
            return {"ok": False, "error": "La memoria no se pudo abrir. Mira la terminal."}
        if not isinstance(titulo, str) or not isinstance(texto, str) or not (ident is None or type(ident) is int):
            return {"ok": False, "error": "Petición incorrecta."}
        clave = None
        if ident is not None:
            dato = self._memoria.leer(ident)
            if dato is None or dato["tipo"] != "nota" or dato["origen"] != "usuario":
                return {"ok": False, "error": "Esa nota no existe."}
            clave = dato["clave"]
        try:
            resultado = self._memoria.guardar_nota(titulo, texto, clave)
        except memoria.ErrorMemoria as error:
            return {"ok": False, "error": str(error)}
        except Exception:
            traceback.print_exc()
            return {"ok": False, "error": "No se pudo guardar. Mira la terminal."}
        return {"ok": True, "estado": resultado["estado"], "memoria": self._datos_memoria()}

    def optimizar_memoria(self):
        """Compacta el archivo y comprueba que está sano. No borra nada."""
        if self._memoria is None:
            return {"ok": False, "error": "La memoria no se pudo abrir. Mira la terminal."}
        try:
            resultado = self._memoria.optimizar()
        except Exception:
            traceback.print_exc()
            return {"ok": False, "error": "No se pudo optimizar. Mira la terminal."}
        return {"ok": True, **resultado, "memoria": self._datos_memoria()}

    # ---------- Sección Biblioteca del panel ----------

    def _estado_biblioteca(self):
        if self._biblioteca is None:
            return None
        try:
            return self._biblioteca.estado()
        except Exception:
            traceback.print_exc()
            return None

    def revisar_biblioteca(self):
        """Botón «Revisar archivos». Compara los archivos exportados con la biblioteca sin cambiar nada."""
        if self._biblioteca is None:
            return {"ok": False, "error": "La biblioteca no se pudo abrir. Mira la terminal."}
        try:
            revision = self._biblioteca.revisar()
        except Exception:
            traceback.print_exc()
            return {"ok": False, "error": "No se pudo revisar. Mira la terminal."}
        # Solo se puede importar lo que se acaba de revisar, sin errores y con cambios.
        self._senal_biblioteca = revision["senal"] if revision["pendiente"] and not revision["errores"] else None
        return {"ok": True, "resumen": revision["resumen"], "errores": revision["errores"],
                "pendiente": revision["pendiente"], "importable": self._senal_biblioteca is not None}

    def importar_biblioteca(self):
        """Botón «Aprobar e importar». Importa exactamente lo revisado. La ventana no manda nada."""
        if self._biblioteca is None:
            return {"ok": False, "error": "La biblioteca no se pudo abrir. Mira la terminal."}
        senal, self._senal_biblioteca = self._senal_biblioteca, None
        if senal is None:
            return {"ok": False, "error": "Primero revisa los archivos."}
        try:
            estado = self._biblioteca.importar(senal)
        except biblioteca.ErrorBiblioteca as error:
            return {"ok": False, "error": str(error)}
        except Exception:
            traceback.print_exc()
            return {"ok": False, "error": "No se pudo importar. Mira la terminal."}
        return {"ok": True, "biblioteca": estado}

    def copia_memoria(self):
        """Botón «Copia de seguridad». Guarda ram535.db con fecha en copias\\memoria."""
        if self._memoria is None:
            return {"ok": False, "error": "La memoria no se pudo abrir. Mira la terminal."}
        try:
            return {"ok": True, **self._memoria.copia()}
        except Exception:
            traceback.print_exc()
            return {"ok": False, "error": "No se pudo hacer la copia. Mira la terminal."}

    def _cerrar_paso(self):
        self._enviar("ram.cerrarPaso", None)

    def _pie(self, pie):
        self._enviar("ram.pie", pie)

    def decidir(self, ident, aprobado):
        """La ventana comunica si el usuario aprueba, aprueba el sitio o rechaza."""
        if type(ident) is not int or not (type(aprobado) is bool or aprobado == "sitio"):
            return {"ok": False}
        with self._candado_permiso:
            pendiente = self._permiso
            if (pendiente is None or pendiente["id"] != ident or pendiente["evento"].is_set()
                    or "opciones" in pendiente):
                return {"ok": False}
            pendiente["aprobado"] = aprobado
            pendiente["evento"].set()
        return {"ok": True}

    def decidir_alta(self, ident, opcion):
        """La ventana comunica qué hacer con un sitio fuera de la lista blanca.
        La línea que se escribe la calcula Python, nunca la ventana."""
        if type(ident) is not int or not isinstance(opcion, str):
            return {"ok": False}
        with self._candado_permiso:
            pendiente = self._permiso
            if (pendiente is None or pendiente["id"] != ident or pendiente["evento"].is_set()
                    or opcion not in pendiente.get("opciones", ())):
                return {"ok": False}
            pendiente["aprobado"] = opcion
            pendiente["evento"].set()
        return {"ok": True}

    def preguntar(self, texto):
        if not isinstance(texto, str) or not texto.strip():
            return {"ok": False, "error": "Escribe algo antes de enviar."}
        if len(texto) > LIMITE_PREGUNTA:
            return {"ok": False, "error": "La pregunta es demasiado larga."}
        if not self._ocupado.acquire(blocking=False):
            return {"ok": False, "error": "Espera a que termine la respuesta anterior."}

        def al_pensar(trozo):
            self._enviar("ram.pensar", trozo)

        def al_escribir(trozo):
            self._enviar("ram.escribir", trozo)

        try:
            respuesta = self._cerebro.preguntar(
                texto.strip(), al_pensar, al_escribir,
                self._pedir_permiso, self._usar, self._cerrar_paso, self._pie,
                self._pedir_alta,
            )
            return {"ok": True, "texto": respuesta}
        except urllib.error.URLError:
            return {"ok": False, "error": "No puedo hablar con Ollama. Comprueba que está abierto."}
        except Exception:
            traceback.print_exc()
            return {"ok": False, "error": "Algo ha fallado. Mira la terminal para ver el detalle."}
        finally:
            self._ocupado.release()
            self._revisar_exposicion()

    def detener(self):
        """Paso 7.4. El botón de parar. No espera al candado, porque la respuesta lo tiene cogido.
        Avisa al cerebro y, si había una tarjeta esperando, la da por rechazada."""
        self._cerebro.parar()
        ident = None
        with self._candado_permiso:
            pendiente = self._permiso
            if pendiente is not None and not pendiente["evento"].is_set():
                pendiente["evento"].set()  # Se queda con su valor por defecto, que es rechazar
                ident = pendiente["id"]
        if ident is not None:
            self._enviar("ram.caducar", ident)
        return {"ok": True}

    def nueva_conversacion(self):
        if not self._ocupado.acquire(blocking=False):
            return {"ok": False, "error": "Espera a que termine la respuesta actual."}
        try:
            self._cerebro.nueva_conversacion()
            self._conversacion_id = None
            return {"ok": True}
        finally:
            self._ocupado.release()

    # ---------- Conversaciones guardadas ----------

    def _lista_conversaciones(self):
        if self._memoria is None:
            return []
        try:
            lista = self._memoria.listar_conversaciones()
        except Exception:
            traceback.print_exc()
            return []
        for c in lista:
            c["actual"] = c["id"] == self._conversacion_id
        return lista

    def guardar_conversacion(self):
        """Botón «Guardar conversación». Guarda tus preguntas y las respuestas finales.
        Si estás siguiendo una conversación reabierta, la actualiza."""
        if self._memoria is None:
            return {"ok": False, "error": "La memoria no se pudo abrir. Mira la terminal."}
        if not self._ocupado.acquire(blocking=False):
            return {"ok": False, "error": "Espera a que termine la respuesta actual."}
        try:
            historial = self._cerebro.historial
            if not historial:
                return {"ok": False, "error": "Todavía no hay nada que guardar."}
            primera = " ".join(historial[0]["content"].split())
            titulo = primera if len(primera) <= LARGO_TITULO else primera[:LARGO_TITULO].rstrip() + "…"
            resultado = self._memoria.guardar_conversacion(titulo, historial, self._conversacion_id)
            self._conversacion_id = resultado["id"]
            return {"ok": True, "estado": resultado["estado"], "conversaciones": self._lista_conversaciones()}
        except memoria.ErrorMemoria as error:
            return {"ok": False, "error": str(error)}
        except Exception:
            traceback.print_exc()
            return {"ok": False, "error": "No se pudo guardar. Mira la terminal."}
        finally:
            self._ocupado.release()

    def abrir_conversacion(self, ident):
        """Recupera una conversación guardada para seguirla."""
        if type(ident) is not int:
            return {"ok": False, "error": "Petición incorrecta."}
        if self._memoria is None:
            return {"ok": False, "error": "La memoria no se pudo abrir. Mira la terminal."}
        if not self._ocupado.acquire(blocking=False):
            return {"ok": False, "error": "Espera a que termine la respuesta actual."}
        try:
            conversacion = self._memoria.abrir_conversacion(ident)
            if conversacion is None:
                return {"ok": False, "error": "Esa conversación ya no existe."}
            if not self._cerebro.cargar_conversacion(conversacion["mensajes"]):
                return {"ok": False, "error": "La conversación guardada no tiene un formato válido."}
            self._conversacion_id = ident
            return {"ok": True, "titulo": conversacion["titulo"], "mensajes": self._cerebro.historial,
                    "conversaciones": self._lista_conversaciones()}
        except Exception:
            traceback.print_exc()
            return {"ok": False, "error": "No se pudo abrir. Mira la terminal."}
        finally:
            self._ocupado.release()

    def borrar_conversacion(self, ident):
        """Borra una conversación guardada. La que tienes en pantalla sigue abierta."""
        if type(ident) is not int:
            return {"ok": False, "error": "Petición incorrecta."}
        if self._memoria is None:
            return {"ok": False, "error": "La memoria no se pudo abrir. Mira la terminal."}
        try:
            borrada = self._memoria.borrar_conversacion(ident)
        except Exception:
            traceback.print_exc()
            return {"ok": False, "error": "No se pudo borrar. Mira la terminal."}
        if ident == self._conversacion_id:
            # Si vuelves a guardar, se crea una conversación nueva.
            self._conversacion_id = None
        return {"ok": borrada, "conversaciones": self._lista_conversaciones()}


carpeta = Path(__file__).parent
plantilla = (carpeta / "index.html").read_text(encoding="utf-8")
script = (carpeta / "ventana.js").read_text(encoding="utf-8")

huella = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
diseno = plantilla.replace("__HUELLA__", f"'sha256-{huella}'").replace("__SCRIPT__", script)

puente = Puente()

ventana = webview.create_window(
    title="RAM535",
    html=diseno,
    width=1000,
    height=700,
    background_color="#0f1115",
    js_api=puente,
    text_select=True,  # Permite seleccionar y copiar texto con Ctrl+C.
)
puente._ventana = ventana
red.al_registrar = puente._al_registrar

# Ajuste 11.4. Icono propio en la ventana y en la barra de tareas. Con un nombre de aplicación
# propio, Windows no la agrupa con otros programas de Python y usa su icono.
ICONO = carpeta / "ram535.ico"
try:
    import ctypes
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("RAM535")
except (AttributeError, OSError):
    pass

print(f"RAM535 versión {VERSION} arrancando")
webview.start(icon=str(ICONO) if ICONO.exists() else None)