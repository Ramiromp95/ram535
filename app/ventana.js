"use strict";

const ram = (() => {
  const conversacion = document.getElementById("conversacion");
  const bienvenida = document.getElementById("bienvenida");
  const formulario = document.getElementById("formulario");
  const caja = document.getElementById("caja");
  const botonEnviar = document.getElementById("enviar");
  const iconoEnviar = document.getElementById("icono-enviar");
  const iconoParar = document.getElementById("icono-parar");
  const botonNueva = document.getElementById("nueva");
  const botonGuardarConv = document.getElementById("guardar-conversacion");
  const estadoTexto = document.getElementById("estado-texto");
  const punto = document.getElementById("punto");

  const botonSeguridad = document.getElementById("seguridad");
  const panelSeguridad = document.getElementById("panel-seguridad");
  const puntoSeguridad = document.getElementById("punto-seguridad");
  const segExposicion = document.getElementById("seg-exposicion");
  const segContadores = document.getElementById("seg-contadores");
  const segVacio = document.getElementById("seg-vacio");
  const segConexiones = document.getElementById("seg-conexiones");
  const segHallazgos = document.getElementById("seg-hallazgos");
  const segTotalProtecciones = document.getElementById("seg-total-protecciones");
  const segProtecciones = document.getElementById("seg-protecciones");
  const segTotalConversaciones = document.getElementById("seg-total-conversaciones");
  const segConversaciones = document.getElementById("seg-conversaciones");
  const memMb = document.getElementById("mem-mb");
  const memDatos = document.getElementById("mem-datos");
  const memRelleno = document.getElementById("mem-relleno");
  const memTotal = document.getElementById("mem-total");
  const memLista = document.getElementById("mem-lista");
  const memNotaPlegable = document.getElementById("mem-nota-plegable");
  const memNotaResumen = document.getElementById("mem-nota-resumen");
  const notaTitulo = document.getElementById("nota-titulo");
  const notaTexto = document.getElementById("nota-texto");
  const notaGuardar = document.getElementById("nota-guardar");
  const notaCancelar = document.getElementById("nota-cancelar");
  const notaEstado = document.getElementById("nota-estado");
  const memOptimizar = document.getElementById("mem-optimizar");
  const memOptimizarEstado = document.getElementById("mem-optimizar-estado");
  const memCopia = document.getElementById("mem-copia");
  let notaEditando = null;
  const bibTotal = document.getElementById("bib-total");
  const bibMb = document.getElementById("bib-mb");
  const bibArchivos = document.getElementById("bib-archivos");
  const bibRevisar = document.getElementById("bib-revisar");
  const bibRevision = document.getElementById("bib-revision");

  let actual = null;
  let ocupado = false;
  let parando = false;
  let dibujoPendiente = false;
  const tarjetas = new Map();

  // ---------- Utilidades ----------

  function crear(etiqueta, clase, texto) {
    const elemento = document.createElement(etiqueta);
    if (clase) elemento.className = clase;
    if (texto !== undefined) elemento.textContent = texto;
    return elemento;
  }

  function bajar() {
    conversacion.scrollTop = conversacion.scrollHeight;
  }

  function ponerEstado(texto, activo) {
    estadoTexto.textContent = texto;
    punto.classList.toggle("activo", activo);
  }

  function ajustarAltura() {
    caja.style.height = "auto";
    caja.style.height = caja.scrollHeight + "px";
  }

  // ---------- Markdown seguro ----------
  // Nunca se usa innerHTML. Todo se construye con elementos y texto plano.

  function enLinea(texto, destino) {
    const patron = /`[^`\n]+`|\*\*[^*\n]+\*\*|\*[^*\s][^*\n]*\*/g;
    let ultimo = 0;
    for (const marca of texto.matchAll(patron)) {
      destino.append(texto.slice(ultimo, marca.index));
      const trozo = marca[0];
      if (trozo.startsWith("`")) {
        destino.append(crear("code", null, trozo.slice(1, -1)));
      } else if (trozo.startsWith("**")) {
        destino.append(crear("strong", null, trozo.slice(2, -2)));
      } else {
        destino.append(crear("em", null, trozo.slice(1, -1)));
      }
      ultimo = marca.index + trozo.length;
    }
    destino.append(texto.slice(ultimo));
  }

  function pintarMarkdown(texto, destino) {
    destino.replaceChildren();
    let lista = null;
    let parrafo = null;
    let codigo = null;

    for (const linea of texto.split("\n")) {
      const limpia = linea.trim();

      if (codigo) {
        if (limpia.startsWith("```")) codigo = null;
        else codigo.append(linea + "\n");
        continue;
      }
      if (limpia.startsWith("```")) {
        lista = parrafo = null;
        const bloque = crear("pre");
        codigo = crear("code");
        bloque.append(codigo);
        destino.append(bloque);
        continue;
      }
      if (limpia === "") {
        lista = parrafo = null;
        continue;
      }

      let partes;
      if ((partes = limpia.match(/^(#{1,6})\s+(.+)$/))) {
        lista = parrafo = null;
        const titulo = crear(partes[1].length <= 2 ? "h3" : "h4");
        enLinea(partes[2], titulo);
        destino.append(titulo);
      } else if (/^(\*{3,}|-{3,}|_{3,})$/.test(limpia)) {
        lista = parrafo = null;
        destino.append(crear("hr"));
      } else if ((partes = limpia.match(/^[-*+]\s+(.+)$/))) {
        parrafo = null;
        if (!lista || lista.tagName !== "UL") {
          lista = crear("ul");
          destino.append(lista);
        }
        const elemento = crear("li");
        enLinea(partes[1], elemento);
        lista.append(elemento);
      } else if ((partes = limpia.match(/^(\d+)[.)]\s+(.+)$/))) {
        parrafo = null;
        if (!lista || lista.tagName !== "OL") {
          lista = crear("ol");
          lista.start = Number(partes[1]);
          destino.append(lista);
        }
        const elemento = crear("li");
        enLinea(partes[2], elemento);
        lista.append(elemento);
      } else {
        lista = null;
        if (parrafo) {
          parrafo.append(crear("br"));
        } else {
          parrafo = crear("p");
          destino.append(parrafo);
        }
        enLinea(limpia, parrafo);
      }
    }
  }

  // ---------- Respuestas en directo ----------

  function nuevaRespuesta() {
    const bloque = crear("div", "mensaje ia");
    const pensamiento = crear("details", "pensamiento");
    const textoPensamiento = crear("div", "texto-pensamiento");
    pensamiento.append(crear("summary", null, "Razonamiento"), textoPensamiento);
    pensamiento.hidden = true;
    const pasos = crear("div", "pasos");
    const respuesta = crear("div", "respuesta");
    const piePagina = crear("div", "pie");
    piePagina.hidden = true;
    bloque.append(pensamiento, pasos, respuesta, piePagina);
    conversacion.append(bloque);
    actual = { pensamiento, textoPensamiento, pasos, respuesta, piePagina, bruto: "" };
  }

  function pensar(trozo) {
    if (!actual) return;
    actual.pensamiento.hidden = false;
    actual.textoPensamiento.append(trozo);
    actual.textoPensamiento.scrollTop = actual.textoPensamiento.scrollHeight;
    ponerEstado("Pensando", true);
    bajar();
  }

  function escribir(trozo) {
    if (!actual) return;
    actual.bruto += trozo;
    ponerEstado("Escribiendo", true);
    if (dibujoPendiente) return;
    dibujoPendiente = true;
    const objetivo = actual;
    requestAnimationFrame(() => {
      dibujoPendiente = false;
      pintarMarkdown(objetivo.bruto, objetivo.respuesta);
      bajar();
    });
  }

  // ---------- Herramientas. Permiso y lecturas ----------

  const DECISIONES = {
    true: "Aprobado",
    sitio: "Aprobado. El sitio queda aprobado en esta pregunta",
    false: "Rechazado",
  };

  function pedirPermiso(peticion) {
    if (!actual) return;
    const tarjeta = crear("div", peticion.automatico ? "tarjeta automatica" : "tarjeta");
    tarjeta.append(crear("p", "tarjeta-titulo", "RAM535 quiere usar " + peticion.nombre));
    tarjeta.append(crear("p", "tarjeta-texto", peticion.descripcion));

    const lista = crear("ul", "tarjeta-direcciones");
    for (const direccion of peticion.direcciones) lista.append(crear("li", null, direccion));
    tarjeta.append(lista);

    const botones = crear("div", "tarjeta-botones");
    tarjeta.append(botones);
    actual.pasos.append(tarjeta);

    // Python ya la dio por aprobada porque el sitio se aprobó antes en esta pregunta.
    if (peticion.automatico) {
      botones.append(crear("span", "tarjeta-estado", "Aprobado. Sitio ya aprobado en esta pregunta"));
      ponerEstado("Consultando", true);
      bajar();
      return;
    }

    const sitios = Array.isArray(peticion.sitios) ? peticion.sitios : [];
    const aprobar = crear("button", "boton-aprobar", "Aprobar");
    const aprobarSitio = crear("button", "boton-suave", sitios.length > 1 ? "Aprobar estos sitios en esta pregunta" : "Aprobar el sitio en esta pregunta");
    const rechazar = crear("button", "boton-suave", "Rechazar");
    aprobarSitio.title = sitios.join(", ");
    for (const boton of [aprobar, aprobarSitio, rechazar]) boton.type = "button";
    aprobar.addEventListener("click", () => decidir(peticion.id, true));
    aprobarSitio.addEventListener("click", () => decidir(peticion.id, "sitio"));
    rechazar.addEventListener("click", () => decidir(peticion.id, false));
    botones.append(aprobar, aprobarSitio, rechazar);

    tarjetas.set(peticion.id, botones);
    ponerEstado("Esperando tu permiso", true);
    bajar();
  }

  async function decidir(id, aprobado) {
    const botones = tarjetas.get(id);
    if (!botones) return;
    tarjetas.delete(id);
    botones.replaceChildren(crear("span", "tarjeta-estado", DECISIONES[aprobado]));
    ponerEstado(aprobado ? "Consultando" : "Pensando", true);
    try {
      await window.pywebview.api.decidir(id, aprobado);
    } catch (fallo) {
      // Si falla, Python lo dará por rechazado al agotar la espera.
    }
  }

  // ---------- Sitio fuera de la lista blanca ----------

  const OPCIONES_ALTA = {
    ruta: "Aceptar y añadir",
    sitio: "Añadir el sitio entero",
    pregunta: "Permitir solo en esta pregunta",
    no: "Mantener bloqueado",
  };
  const ESTADOS_ALTA = {
    ruta: "Ruta añadida a tu lista blanca",
    sitio: "Sitio añadido a tu lista blanca",
    pregunta: "Permitido solo en esta pregunta",
    no: "Bloqueado",
  };

  function pedirAlta(peticion) {
    if (!actual) return;
    const tarjeta = crear("div", "tarjeta bloqueo");
    tarjeta.append(crear("p", "tarjeta-titulo", "Sitio fuera de tu lista blanca"));
    tarjeta.append(crear("p", "tarjeta-texto", "RAM535 quiere usar " + peticion.nombre + ". " + peticion.descripcion));
    const lista = crear("ul", "tarjeta-direcciones");
    lista.append(crear("li", null, peticion.url));
    tarjeta.append(lista);

    const botones = crear("div", "tarjeta-botones");
    tarjeta.append(botones);
    actual.pasos.append(tarjeta);
    tarjetas.set(peticion.id, botones);
    mostrarOpcionesAlta(peticion, botones);
    ponerEstado("Esperando tu permiso", true);
    bajar();
  }

  function mostrarOpcionesAlta(peticion, botones) {
    botones.replaceChildren();
    for (const opcion of Object.keys(OPCIONES_ALTA)) {
      if (opcion === "ruta" && !peticion.linea_ruta) continue;
      const boton = crear("button", "boton-suave", OPCIONES_ALTA[opcion]);
      boton.type = "button";
      boton.addEventListener("click", () => {
        // Ajuste 7.3. La ruta exacta se añade con un clic. El sitio entero abre mucho más
        // y sigue pidiendo un segundo clic con la línea exacta.
        if (opcion === "sitio") confirmarAlta(peticion, botones, opcion);
        else decidirAlta(peticion.id, opcion);
      });
      botones.append(boton);
    }
  }

  // Segundo clic. Enseña la línea exacta que Python escribirá en lista_blanca.txt.
  function confirmarAlta(peticion, botones, opcion) {
    const linea = opcion === "ruta" ? peticion.linea_ruta : peticion.linea_sitio;
    const caja = crear("div", "tarjeta-confirmacion");
    caja.append(crear("p", "tarjeta-texto", "Se añadirá esta línea al final de lista_blanca.txt"));
    caja.append(crear("p", "tarjeta-linea", linea));
    const fila = crear("div", "tarjeta-botones");
    const confirmar = crear("button", "boton-aprobar", "Confirmar");
    const volver = crear("button", "boton-suave", "Volver");
    confirmar.type = "button";
    volver.type = "button";
    confirmar.addEventListener("click", () => decidirAlta(peticion.id, opcion));
    volver.addEventListener("click", () => mostrarOpcionesAlta(peticion, botones));
    fila.append(confirmar, volver);
    caja.append(fila);
    botones.replaceChildren(caja);
  }

  async function decidirAlta(id, opcion) {
    const botones = tarjetas.get(id);
    if (!botones) return;
    tarjetas.delete(id);
    botones.replaceChildren(crear("span", "tarjeta-estado", ESTADOS_ALTA[opcion]));
    ponerEstado(opcion === "no" ? "Pensando" : "Consultando", true);
    try {
      await window.pywebview.api.decidir_alta(id, opcion);
    } catch (fallo) {
      // Si falla, Python lo dará por bloqueado al agotar la espera.
    }
  }

  function caducar(id) {
    const botones = tarjetas.get(id);
    if (!botones) return;
    tarjetas.delete(id);
    botones.replaceChildren(crear("span", "tarjeta-estado", "Sin respuesta. Rechazado"));
  }

  function cerrarPaso() {
    if (!actual) return;
    const texto = actual.bruto.trim();
    actual.bruto = "";
    actual.respuesta.replaceChildren();
    if (texto) actual.pasos.append(crear("div", "nota-paso", texto));
  }

  function usar(uso) {
    if (!actual) return;
    const bloque = crear("details", "lectura");
    const PREFIJOS = { consultar_memoria: "Memoria", consultar_biblioteca: "Biblioteca", buscar_web: "Búsqueda" };
    const base = PREFIJOS[uso.nombre] || "Lectura";
    const prefijo = base + (uso.ok ? ". " : " fallida. ");
    const titulo = prefijo + uso.descripcion;
    bloque.append(crear("summary", null, titulo), crear("div", "texto-lectura", uso.vista));
    if (Number.isInteger(uso.guardable)) ponerGuardar(bloque, uso.guardable);
    actual.pasos.append(bloque);
    bajar();
  }

  // ---------- Guardar en memoria ----------
  // La ventana solo manda el número de la lectura. Los datos los tiene Python.

  function plural(n, uno, varios) {
    return n === 1 ? "1 " + uno : n + " " + varios;
  }

  function resumenGuardado(r) {
    const partes = [];
    if (r.nuevos) partes.push(plural(r.nuevos, "dato nuevo", "datos nuevos"));
    if (r.versiones) partes.push(plural(r.versiones, "versión nueva", "versiones nuevas"));
    if (!partes.length) return "Ya estaba en memoria, sin cambios";
    if (r.iguales) partes.push(plural(r.iguales, "sin cambios", "sin cambios"));
    return "Guardado en memoria. " + partes.join(", ");
  }

  function ponerGuardar(bloque, id) {
    const acciones = crear("div", "acciones");
    const boton = crear("button", "boton-copiar", "Guardar en memoria");
    boton.type = "button";
    boton.addEventListener("click", async () => {
      boton.disabled = true;
      boton.textContent = "Guardando";
      let resultado;
      try {
        resultado = await window.pywebview.api.guardar_lectura(id);
      } catch (fallo) {
        resultado = { ok: false, error: "No se pudo guardar." };
      }
      if (resultado && resultado.ok) {
        boton.textContent = resumenGuardado(resultado);
      } else {
        boton.textContent = (resultado && resultado.error) || "No se pudo guardar.";
        // Si no se guardó nada, se puede volver a intentar.
        boton.disabled = !!(resultado && (resultado.nuevos || resultado.versiones || resultado.iguales));
      }
    });
    acciones.append(boton);
    bloque.append(acciones);
  }

  // El pie lo escribe Python con lo que de verdad se consultó, no la IA.
  function pie(datos) {
    if (!actual) return;
    const secciones = [
      ["Fuentes consultadas", datos.fuentes],
      ["Consultas rechazadas", datos.rechazadas],
      ["Consultas fallidas", datos.fallidas],
    ];
    for (const [titulo, elementos] of secciones) {
      if (!elementos || elementos.length === 0) continue;
      actual.piePagina.append(crear("p", "pie-titulo", titulo));
      const lista = crear("ul");
      for (const elemento of elementos) lista.append(crear("li", null, elemento));
      actual.piePagina.append(lista);
    }
    actual.piePagina.hidden = false;
  }

  // ---------- Panel de seguridad ----------
  // Python manda solo lo que ha cambiado. Cada parte se pinta por separado.

  const RESULTADOS = {
    OK: ["Descargadas", "OK"],
    REDIRECCION: ["Redirecciones", "Redirección"],
    SIN_ROBOTS: ["Sin robots.txt", "Sin robots"],
    BLOQUEADO: ["Bloqueadas", "Bloqueada"],
    ERROR: ["Errores", "Error"],
    ALTA: ["Altas en la lista", "Alta en la lista"],
  };

  function texto(valor) {
    return typeof valor === "string" ? valor : String(valor ?? "");
  }

  function fila(ok, contenido) {
    const elemento = crear("li", "seg-fila" + (ok === true ? " bien" : ok === false ? " mal" : ""));
    elemento.append(crear("span", "seg-marca"), crear("span", null, contenido));
    return elemento;
  }

  function pintarExposicion(comprobaciones) {
    segExposicion.replaceChildren();
    let todoBien = comprobaciones.length > 0;
    for (const c of comprobaciones) {
      if (c.ok !== true) todoBien = false;
      segExposicion.append(fila(c.ok === true, texto(c.texto)));
    }
    puntoSeguridad.classList.toggle("bien", todoBien);
    puntoSeguridad.classList.toggle("mal", !todoBien);
  }

  function pintarConexiones(datos) {
    const contadores = datos.contadores || {};
    const ultimas = Array.isArray(datos.ultimas) ? datos.ultimas : [];

    segContadores.replaceChildren();
    for (const [clave, [nombre]] of Object.entries(RESULTADOS)) {
      const caja = crear("div", "seg-contador seg-" + clave.toLowerCase());
      caja.append(crear("span", "seg-numero", texto(contadores[clave] ?? 0)), crear("span", "seg-etiqueta", nombre));
      segContadores.append(caja);
    }

    segConexiones.replaceChildren();
    segVacio.hidden = ultimas.length > 0;
    for (const c of ultimas) {
      const resultado = texto(c.resultado);
      const conocido = RESULTADOS[resultado];
      const elemento = crear("li", "seg-conexion");
      const cabeza = crear("div", "seg-conexion-cabeza");
      const clase = "seg-resultado" + (conocido ? " seg-" + resultado.toLowerCase() : "");
      const hora = texto(c.fecha).split("T")[1] || texto(c.fecha);
      cabeza.append(crear("span", clase, conocido ? conocido[1] : resultado), crear("span", "seg-hora", hora));
      elemento.append(cabeza, crear("div", "seg-url", texto(c.url)));
      if (resultado !== "OK" && c.detalle) elemento.append(crear("div", "seg-detalle", texto(c.detalle)));
      segConexiones.append(elemento);
    }
  }

  function pintarHallazgos(hallazgos) {
    segHallazgos.replaceChildren();
    if (hallazgos.length === 0) {
      segHallazgos.append(crear("p", "seg-vacio", "Ningún hallazgo abierto."));
      return;
    }
    for (const h of hallazgos) {
      const tarjeta = crear("div", "seg-hallazgo");
      const cabeza = crear("div", "seg-hallazgo-cabeza");
      cabeza.append(crear("span", null, texto(h.id)), crear("span", null, texto(h.estado)));
      tarjeta.append(
        cabeza,
        crear("p", "seg-hallazgo-titulo", texto(h.titulo)),
        crear("p", "seg-hallazgo-detalle", texto(h.detalle)),
      );
      segHallazgos.append(tarjeta);
    }
  }

  function pintarProtecciones(protecciones) {
    segTotalProtecciones.textContent = protecciones.length + " capas activas";
    segProtecciones.replaceChildren(...protecciones.map((p) => fila(true, texto(p))));
  }

  function panel(datos) {
    if (!datos || typeof datos !== "object") return;
    if (Array.isArray(datos.exposicion)) pintarExposicion(datos.exposicion);
    if (datos.conexiones && typeof datos.conexiones === "object") pintarConexiones(datos.conexiones);
    if (Array.isArray(datos.hallazgos)) pintarHallazgos(datos.hallazgos);
    if (Array.isArray(datos.protecciones)) pintarProtecciones(datos.protecciones);
    if (Array.isArray(datos.conversaciones)) pintarConversaciones(datos.conversaciones);
    if ("memoria" in datos) pintarMemoria(datos.memoria);
    if ("biblioteca" in datos) pintarBiblioteca(datos.biblioteca);
  }

  function plegarPanel() {
    const abrir = panelSeguridad.hidden;
    panelSeguridad.hidden = !abrir;
    botonSeguridad.setAttribute("aria-expanded", String(abrir));
  }

  async function cargarPanel() {
    try {
      panel(await window.pywebview.api.estado_panel());
    } catch (fallo) {
      pintarExposicion([{ ok: false, texto: "No he podido leer el estado de seguridad." }]);
    }
  }

  // ---------- Conversaciones guardadas ----------
  // La ventana solo manda números. Lo que se guarda lo saca Python de su historial.

  function avisoBoton(boton, mensaje, original) {
    boton.textContent = mensaje;
    setTimeout(() => { boton.textContent = original; }, 2000);
  }

  function pintarConversaciones(lista) {
    segTotalConversaciones.textContent = lista.length === 0
      ? "Ninguna todavía"
      : lista.length === 1 ? "1 conversación" : lista.length + " conversaciones";
    segConversaciones.replaceChildren();
    for (const c of lista) {
      if (!Number.isInteger(c.id)) continue;
      const elemento = crear("li", "seg-conversacion" + (c.actual ? " actual" : ""));
      const fecha = texto(c.actualizada).replace("T", " ").slice(0, 16);
      const botones = crear("div", "seg-conv-botones");
      const abrir = crear("button", null, c.actual ? "Abierta" : "Abrir");
      const borrar = crear("button", null, "Borrar");
      abrir.type = "button";
      borrar.type = "button";
      abrir.disabled = !!c.actual;
      abrir.addEventListener("click", () => abrirConversacion(c.id));
      // Borrar pide un segundo clic. Si no llega en 4 segundos, se cancela.
      let espera = null;
      borrar.addEventListener("click", async () => {
        if (!espera) {
          borrar.textContent = "Confirmar borrado";
          borrar.classList.add("peligro");
          espera = setTimeout(() => {
            espera = null;
            borrar.textContent = "Borrar";
            borrar.classList.remove("peligro");
          }, 4000);
          return;
        }
        clearTimeout(espera);
        borrar.disabled = true;
        try {
          const r = await window.pywebview.api.borrar_conversacion(c.id);
          if (r && Array.isArray(r.conversaciones)) pintarConversaciones(r.conversaciones);
        } catch (fallo) {
          borrar.textContent = "No se pudo borrar";
        }
      });
      botones.append(abrir, borrar);
      elemento.append(crear("div", "seg-conv-titulo", texto(c.titulo)), crear("div", "seg-conv-fecha", fecha), botones);
      segConversaciones.append(elemento);
    }
  }

  async function guardarConversacion() {
    if (ocupado) return;
    const original = "Guardar conversación";
    botonGuardarConv.disabled = true;
    botonGuardarConv.textContent = "Guardando";
    let r;
    try {
      r = await window.pywebview.api.guardar_conversacion();
    } catch (fallo) {
      r = { ok: false, error: "No se pudo guardar." };
    }
    botonGuardarConv.disabled = false;
    if (r && r.ok) {
      avisoBoton(botonGuardarConv, r.estado === "actualizada" ? "Actualizada" : "Guardada", original);
      if (Array.isArray(r.conversaciones)) pintarConversaciones(r.conversaciones);
    } else {
      avisoBoton(botonGuardarConv, (r && r.error) || "No se pudo guardar.", original);
    }
  }

  function pintarRecuperada(mensajes) {
    conversacion.replaceChildren(bienvenida);
    bienvenida.hidden = true;
    conversacion.append(crear("div", "nota-paso", "Conversación guardada recuperada. Puedes seguirla."));
    for (const m of mensajes) {
      if (!m || typeof m.content !== "string") continue;
      if (m.role === "user") {
        conversacion.append(crear("div", "mensaje tu", m.content));
      } else if (m.role === "assistant") {
        const bloque = crear("div", "mensaje ia");
        const respuesta = crear("div", "respuesta");
        bloque.append(respuesta);
        conversacion.append(bloque);
        pintarMarkdown(m.content, respuesta);
        ponerCopiar({ respuesta }, m.content);
      }
    }
    bajar();
  }

  async function abrirConversacion(id) {
    if (ocupado) return;
    let r;
    try {
      r = await window.pywebview.api.abrir_conversacion(id);
    } catch (fallo) {
      r = { ok: false, error: "No se pudo abrir." };
    }
    if (r && r.ok && Array.isArray(r.mensajes)) {
      pintarRecuperada(r.mensajes);
      if (Array.isArray(r.conversaciones)) pintarConversaciones(r.conversaciones);
      caja.focus();
    } else {
      segTotalConversaciones.textContent = (r && r.error) || "No se pudo abrir.";
    }
  }

  // ---------- Sección Memoria del panel ----------
  // La ventana solo manda números. La excepción son tus notas, que escribes tú.

  const TIPOS = { cve: "CVE", pagina: "Página", noticia: "Noticia", nota: "Nota tuya" };

  function confirmarDosVeces(boton, accion) {
    let espera = null;
    boton.addEventListener("click", () => {
      if (!espera) {
        boton.textContent = "Confirmar borrado";
        boton.classList.add("peligro");
        espera = setTimeout(() => {
          espera = null;
          boton.textContent = "Borrar";
          boton.classList.remove("peligro");
        }, 4000);
        return;
      }
      clearTimeout(espera);
      boton.disabled = true;
      accion();
    });
  }

  function pintarMemoria(m) {
    if (!m || typeof m !== "object" || !m.estado) {
      memMb.textContent = "La memoria no se pudo abrir";
      memDatos.textContent = "";
      return;
    }
    const e = m.estado;
    const porcentaje = Math.min(100, Number(e.porcentaje) || 0);
    memMb.textContent = texto(e.mb) + " MB de " + texto(e.limite_mb) + " MB";
    memDatos.textContent = plural(Number(e.datos) || 0, "dato", "datos") + ", "
      + plural(Number(e.versiones) || 0, "versión", "versiones");
    memRelleno.style.width = porcentaje + "%";
    memRelleno.classList.toggle("aviso", !!e.aviso && porcentaje < 100);
    memRelleno.classList.toggle("lleno", porcentaje >= 100);

    const ultimos = Array.isArray(m.ultimos) ? m.ultimos : [];
    memTotal.textContent = ultimos.length ? "Últimos datos guardados (" + ultimos.length + ")" : "Todavía no hay datos guardados";
    memLista.replaceChildren();
    for (const d of ultimos) {
      if (!Number.isInteger(d.id)) continue;
      const elemento = crear("li", "seg-conversacion");
      const fecha = texto(d.fecha).replace("T", " ").slice(0, 16);
      let detalle = (TIPOS[d.tipo] || texto(d.tipo)) + " · " + fecha;
      if (d.versiones > 1) detalle += " · " + d.versiones + " versiones";
      const botones = crear("div", "seg-conv-botones");
      if (d.tipo === "nota" && d.origen === "usuario") {
        const editar = crear("button", null, "Editar");
        editar.type = "button";
        editar.addEventListener("click", () => editarNota(d.id));
        botones.append(editar);
      }
      const borrar = crear("button", null, "Borrar");
      borrar.type = "button";
      confirmarDosVeces(borrar, async () => {
        try {
          const r = await window.pywebview.api.borrar_dato(d.id);
          if (r && "memoria" in r) pintarMemoria(r.memoria);
          if (notaEditando === d.id) limpiarNota("");
        } catch (fallo) {
          borrar.textContent = "No se pudo borrar";
        }
      });
      botones.append(borrar);
      elemento.append(crear("div", "seg-conv-titulo", texto(d.titulo)), crear("div", "seg-conv-fecha", detalle), botones);
      memLista.append(elemento);
    }
  }

  function limpiarNota(mensaje) {
    notaEditando = null;
    notaTitulo.value = "";
    notaTexto.value = "";
    notaGuardar.textContent = "Guardar nota";
    notaCancelar.hidden = true;
    memNotaResumen.textContent = "Escribir una nota";
    notaEstado.textContent = mensaje;
  }

  async function editarNota(id) {
    let r;
    try {
      r = await window.pywebview.api.leer_nota(id);
    } catch (fallo) {
      r = { ok: false, error: "No se pudo abrir la nota." };
    }
    if (!r || !r.ok) {
      notaEstado.textContent = (r && r.error) || "No se pudo abrir la nota.";
      return;
    }
    notaEditando = r.id;
    notaTitulo.value = texto(r.titulo);
    notaTexto.value = texto(r.texto);
    notaGuardar.textContent = "Guardar cambios";
    notaCancelar.hidden = false;
    memNotaResumen.textContent = "Editando una nota";
    notaEstado.textContent = "Al guardar se crea una versión nueva y la anterior se conserva.";
    memNotaPlegable.open = true;
    notaTexto.focus();
  }

  async function guardarNota() {
    const titulo = notaTitulo.value.trim();
    const contenido = notaTexto.value.trim();
    if (!titulo || !contenido) {
      notaEstado.textContent = "Escribe un título y la nota.";
      return;
    }
    notaGuardar.disabled = true;
    let r;
    try {
      r = await window.pywebview.api.guardar_nota(titulo, contenido, notaEditando);
    } catch (fallo) {
      r = { ok: false, error: "No se pudo guardar." };
    }
    notaGuardar.disabled = false;
    if (r && r.ok) {
      const mensajes = { nuevo: "Nota guardada.", version: "Versión nueva guardada.", igual: "No había cambios." };
      limpiarNota(mensajes[r.estado] || "Nota guardada.");
      if ("memoria" in r) pintarMemoria(r.memoria);
    } else {
      notaEstado.textContent = (r && r.error) || "No se pudo guardar.";
    }
  }

  async function optimizarMemoria() {
    memOptimizar.disabled = true;
    memOptimizarEstado.textContent = "Optimizando";
    let r;
    try {
      r = await window.pywebview.api.optimizar_memoria();
    } catch (fallo) {
      r = { ok: false, error: "No se pudo optimizar." };
    }
    memOptimizar.disabled = false;
    if (r && r.ok) {
      let aviso = r.integridad ? "Archivo sano. " : "ALERTA, el archivo tiene daños. ";
      if (r.huellas_mal) aviso += "ALERTA, " + plural(r.huellas_mal, "dato no coincide", "datos no coinciden") + " con su huella. ";
      memOptimizarEstado.textContent = aviso + texto(r.antes_mb) + " MB antes, " + texto(r.despues_mb) + " MB ahora.";
      if ("memoria" in r) pintarMemoria(r.memoria);
    } else {
      memOptimizarEstado.textContent = (r && r.error) || "No se pudo optimizar.";
    }
  }

  async function copiaMemoria() {
    memCopia.disabled = true;
    memOptimizarEstado.textContent = "Haciendo la copia";
    let r;
    try {
      r = await window.pywebview.api.copia_memoria();
    } catch (fallo) {
      r = { ok: false, error: "No se pudo hacer la copia." };
    }
    memCopia.disabled = false;
    if (r && r.ok) {
      memOptimizarEstado.textContent = (r.integridad ? "Copia sana guardada en copias\\memoria\\" : "ALERTA, la copia tiene daños. ")
        + texto(r.nombre) + " (" + texto(r.mb) + " MB).";
    } else {
      memOptimizarEstado.textContent = (r && r.error) || "No se pudo hacer la copia.";
    }
  }

  // ---------- Sección Biblioteca del panel ----------
  // La ventana pide revisar e importar. Qué se importa lo decide Python con su revisión.

  function pintarBiblioteca(b) {
    if (!b || typeof b !== "object") {
      bibTotal.textContent = "La biblioteca no se pudo abrir";
      bibMb.textContent = "";
      return;
    }
    const total = Number(b.fichas) || 0;
    bibTotal.textContent = total ? plural(total, "ficha", "fichas") : "Todavía vacía";
    bibMb.textContent = total ? texto(b.mb) + " MB" : "";
    bibArchivos.replaceChildren();
    for (const a of Array.isArray(b.archivos) ? b.archivos : []) {
      const elemento = crear("li", "seg-conversacion");
      const importado = texto(a.importado).replace("T", " ").slice(0, 16);
      elemento.append(
        crear("div", "seg-conv-titulo", texto(a.titulo)),
        crear("div", "seg-conv-fecha", plural(Number(a.total) || 0, "ficha", "fichas")
          + " · exportado " + texto(a.exportado) + " · importado " + importado),
      );
      bibArchivos.append(elemento);
    }
  }

  function listaEjemplos(titulo, ejemplos, total) {
    const bloque = crear("div");
    if (!total) return bloque;
    bloque.append(crear("div", "bib-cifras", titulo));
    const lista = crear("ul", "bib-ejemplos");
    for (const e of Array.isArray(ejemplos) ? ejemplos : []) lista.append(crear("li", null, texto(e)));
    if (total > (ejemplos || []).length) lista.append(crear("li", null, "y " + (total - ejemplos.length) + " más"));
    bloque.append(lista);
    return bloque;
  }

  function pintarRevision(r) {
    bibRevision.replaceChildren();
    const caja = crear("div", "bib-cambios");
    for (const a of Array.isArray(r.resumen) ? r.resumen : []) {
      const elemento = crear("div", "bib-artefacto");
      const n = Number(a.nuevas) || 0, c = Number(a.cambiadas) || 0, e = Number(a.eliminadas) || 0;
      elemento.append(
        crear("div", "seg-conv-titulo", texto(a.titulo) + " · exportado " + texto(a.exportado)),
        crear("div", "bib-cifras", n + " nuevas, " + c + " cambiadas, " + e + " eliminadas, "
          + (Number(a.iguales) || 0) + " iguales"),
        crear("div", "bib-cifras", "Huella " + texto(a.huella).slice(0, 16)),
        listaEjemplos("Nuevas", a.ejemplos_nuevas, n),
        listaEjemplos("Cambiadas", a.ejemplos_cambiadas, c),
        listaEjemplos("Eliminadas", a.ejemplos_eliminadas, e),
      );
      caja.append(elemento);
    }
    for (const error of Array.isArray(r.errores) ? r.errores : []) caja.append(crear("p", "bib-error", texto(error)));
    bibRevision.append(caja);

    if (r.errores && r.errores.length) {
      bibRevision.append(crear("p", "bib-aviso", "No se importa nada hasta que todos los archivos estén bien. Pídeme que los exporte de nuevo."));
      return;
    }
    if (!r.pendiente) {
      bibRevision.append(crear("p", "bib-aviso", "La biblioteca está al día. No hay nada que importar."));
      return;
    }
    if (!r.importable) return;
    const botones = crear("div", "seg-conv-botones mem-bloque");
    const importar = crear("button", null, "Aprobar e importar");
    importar.type = "button";
    let confirmar = false;
    importar.addEventListener("click", async () => {
      if (!confirmar) {
        confirmar = true;
        importar.textContent = "Confirmar importación";
        importar.classList.add("peligro");
        return;
      }
      importar.disabled = true;
      importar.textContent = "Importando";
      let res;
      try {
        res = await window.pywebview.api.importar_biblioteca();
      } catch (fallo) {
        res = { ok: false, error: "No se pudo importar." };
      }
      if (res && res.ok) {
        bibRevision.replaceChildren(crear("p", "bib-aviso", "Importado. La IA ya puede consultar tu biblioteca."));
        pintarBiblioteca(res.biblioteca);
      } else {
        bibRevision.append(crear("p", "bib-error", (res && res.error) || "No se pudo importar."));
        importar.remove();
      }
    });
    botones.append(importar);
    bibRevision.append(botones);
  }

  async function revisarBiblioteca() {
    bibRevisar.disabled = true;
    bibRevision.replaceChildren(crear("p", "bib-aviso", "Revisando"));
    let r;
    try {
      r = await window.pywebview.api.revisar_biblioteca();
    } catch (fallo) {
      r = { ok: false, error: "No se pudo revisar." };
    }
    bibRevisar.disabled = false;
    if (r && r.ok) pintarRevision(r);
    else bibRevision.replaceChildren(crear("p", "bib-error", (r && r.error) || "No se pudo revisar."));
  }

  // ---------- Copiar una respuesta ----------

  async function copiarTexto(texto, boton) {
    let copiado = false;
    try {
      await navigator.clipboard.writeText(texto);
      copiado = true;
    } catch (fallo) {
      // Plan B. Un cuadro de texto invisible y la orden clásica de copiar.
      const temporal = crear("textarea");
      temporal.value = texto;
      temporal.setAttribute("readonly", "");
      temporal.style.position = "fixed";
      temporal.style.opacity = "0";
      document.body.append(temporal);
      temporal.select();
      try { copiado = document.execCommand("copy"); } catch (otro) { copiado = false; }
      temporal.remove();
    }
    boton.textContent = copiado ? "Copiado" : "No se pudo copiar";
    setTimeout(() => { boton.textContent = "Copiar"; }, 1500);
  }

  function ponerCopiar(bloque, texto) {
    if (!texto) return;
    const acciones = crear("div", "acciones");
    const boton = crear("button", "boton-copiar", "Copiar");
    boton.type = "button";
    boton.addEventListener("click", () => copiarTexto(texto, boton));
    acciones.append(boton);
    bloque.respuesta.after(acciones);
  }

  // ---------- Enviar y nueva conversación ----------

  // Paso 7.4. Mientras responde, el botón de enviar se convierte en el de parar.
  function modoParar(activo) {
    parando = false;
    botonEnviar.classList.toggle("parar", activo);
    iconoEnviar.hidden = activo;
    iconoParar.hidden = !activo;
    botonEnviar.setAttribute("aria-label", activo ? "Parar" : "Enviar");
    botonEnviar.disabled = false;
  }

  async function detener() {
    if (!ocupado || parando) return;
    parando = true;
    botonEnviar.disabled = true;
    ponerEstado("Parando", true);
    try {
      await window.pywebview.api.detener();
    } catch (fallo) {
      // Si falla, la respuesta seguirá hasta el final.
    }
  }

  async function enviar() {
    const texto = caja.value.trim();
    if (!texto || ocupado) return;

    ocupado = true;
    modoParar(true);
    bienvenida.hidden = true;
    conversacion.append(crear("div", "mensaje tu", texto));
    caja.value = "";
    ajustarAltura();
    nuevaRespuesta();
    ponerEstado("Pensando", true);
    bajar();

    let resultado;
    try {
      resultado = await window.pywebview.api.preguntar(texto);
    } catch (fallo) {
      resultado = { ok: false, error: "No he podido hablar con Python." };
    }

    const terminada = actual;
    actual = null;
    if (resultado && resultado.ok) {
      terminada.bruto = resultado.texto;
      pintarMarkdown(terminada.bruto, terminada.respuesta);
      ponerCopiar(terminada, terminada.bruto);
    } else {
      const aviso = (resultado && resultado.error) || "Error desconocido.";
      terminada.respuesta.append(crear("p", "error", aviso));
    }

    ocupado = false;
    modoParar(false);
    ponerEstado("Modo local", false);
    bajar();
    caja.focus();
  }

  async function nuevaConversacion() {
    if (ocupado) return;
    const resultado = await window.pywebview.api.nueva_conversacion();
    if (resultado && resultado.ok) {
      conversacion.replaceChildren(bienvenida);
      bienvenida.hidden = false;
      caja.focus();
      cargarPanel();  // Ninguna conversación guardada queda marcada como abierta
    }
  }

  // ---------- Eventos y arranque ----------

  formulario.addEventListener("submit", (evento) => {
    evento.preventDefault();
    if (ocupado) detener();
    else enviar();
  });

  caja.addEventListener("keydown", (evento) => {
    if (evento.key === "Enter" && !evento.shiftKey && !evento.isComposing) {
      evento.preventDefault();
      enviar();
    }
  });

  caja.addEventListener("input", ajustarAltura);
  botonNueva.addEventListener("click", nuevaConversacion);
  botonGuardarConv.addEventListener("click", guardarConversacion);
  notaGuardar.addEventListener("click", guardarNota);
  notaCancelar.addEventListener("click", () => limpiarNota(""));
  memOptimizar.addEventListener("click", optimizarMemoria);
  memCopia.addEventListener("click", copiaMemoria);
  bibRevisar.addEventListener("click", revisarBiblioteca);
  botonSeguridad.addEventListener("click", plegarPanel);

  function listo() {
    caja.disabled = false;
    botonEnviar.disabled = false;
    ponerEstado("Modo local", false);
    caja.focus();
    cargarPanel();
  }

  if (window.pywebview && window.pywebview.api && window.pywebview.api.preguntar) {
    listo();
  } else {
    window.addEventListener("pywebviewready", listo);
  }

  return Object.freeze({ pensar, escribir, pedirPermiso, pedirAlta, caducar, usar, cerrarPaso, pie, panel });
})();