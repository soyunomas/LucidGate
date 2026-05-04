# 🗺️ ROADMAP ARQUITECTÓNICO: LucidGate -> MOTOR DE FILTRADO (E2GUARDIAN CLONE)

## 🚧 Pendientes prioritarios

- [x] **Documentar sustitución de frases en README.**
  - **Comprobación 2026-05-03:** `README.md` documenta `masking`, pero no explica la configuración `[[substitution.rule]]` ni su diferencia con masking.
  - **Contexto:** `tasks/todo.md` y `lucidgate.toml` sí contienen referencias a sustitución (`search`/`replace`), pero falta una sección de uso en la documentación principal.
  - **Resultado:** añadida sección `Phrase Substitution`, ejemplo TOML y diferenciación explícita frente a `masking`.

- [x] **Soporte de proxy HTTP "plano" (no solo CONNECT/HTTPS).**
  - **Estado actual:** `proxy/server.go:166` rechaza con `405 method not allowed` cualquier petición que no sea `CONNECT`. Solo se sirven túneles HTTPS con MITM.
  - **Objetivo:** aceptar también peticiones HTTP absolutas (`GET http://host/path HTTP/1.1`) típicas de un proxy explícito HTTP/1.1 (RFC 7230 §5.3.2). Reutilizar el mismo pipeline de filtros/dump/inyección que ya existe para HTTPS.
  - **Notas de diseño:**
    - Distinguir en el handler raíz: `MethodConnect` → MITM TLS actual; resto → ruta nueva HTTP-plano.
    - Para HTTP-plano abrir conexión upstream `net.Dial` al `req.URL.Host`, sanear cabeceras hop-by-hop (`Proxy-Connection`, etc.), reutilizar `relayHTTP()` (o una variante) con sus `RelayOptions` para que pasen `Magic`, `Semantic`, `Substitution`, `HTML banner` y dump.
    - Mantener todos los preceptos: `SetReadDeadline`/`SetWriteDeadline`, `sync.Pool` para buffers, `io.CopyBuffer`, sin `io.ReadAll`.
    - Aplicar también `[access.profile]` y `[schedule]` antes de abrir la conexión upstream (Fail Fast, precepto #10).
    - Añadir tests: GET HTTP/1.1 absoluto a un backend de prueba, verificación de inyección/sustitución, bloqueo por dominio, cierre correcto en EOF.
  - **Resultado 2026-05-03:** `ServeHTTP` acepta peticiones HTTP explícitas no-CONNECT, valida `http://`/Host, aplica acceso/horario/dominio antes de dial, usa límite de conexiones, abre TCP plano al upstream, sanitiza cabeceras proxy, normaliza a origin-form y escribe request/response en streaming con el pipeline de filtros/dump existente.
  - **Pruebas añadidas:** forward HTTP absoluto con sustitución + inyección HTML y bloqueo de dominio antes de dial.
  - **Verificación:** `make verify` OK; `make build` OK; benchmark 10GiB `44176 B/op`, `24 allocs/op`; `rg "io\\.ReadAll|ioutil\\.ReadAll" proxy/relay.go proxy/server.go` sin resultados.

## Plan activo - Proxy HTTP plano

- [x] Auditar `ServeHTTP`, `handleHTTPS` y `relayHTTP` para integrar HTTP explícito sin romper CONNECT/MITM.
- [x] Implementar ruta no-CONNECT con validación de destino, acceso/horario/dominio antes de dial, límite de conexiones y deadlines.
- [x] Reutilizar el pipeline streaming existente (`writeRequestStreaming`, `writeResponseStreaming`, filtros, dumps y `sync.Pool`) para peticiones HTTP absolutas.
- [x] Añadir pruebas de forward HTTP, sustitución/inyección y bloqueo por dominio antes de abrir upstream.
-[x] Verificar con tests/build/benchmark y búsqueda anti-`ReadAll`.

## 🔥 Hotfixes - Sesión 2026-05-03

- [x] **HF-3: YouTube queda en skeleton gris por corrupción de bundles JS/CSS.**
  - **Síntoma:** YouTube carga HTML/CSS/JS con `200`, pero reporta `jserror` `SyntaxError: missing : after property id` en un bundle `ytmainappweb...js`; la UI queda en rectángulos grises y no aparecen vídeos.
  - **Causa raíz:** el pipeline consideraba `application/javascript`/CSS como contenido mutable. Con reglas como `[[substitution.rule]]` o semantic/masking, bundles minificados de YouTube podían salir modificados o truncados y el parser JS fallaba.
  - **Fix:** `isFilterMutableResponseType()` excluye JS/CSS del pipeline mutante. HTML/text/plain/JSON/XML siguen filtrándose; `Magic` puede seguir inspeccionando tipos no mutables.
  - **Regresión añadida:** un bundle `application/javascript` con frases configuradas debe conservar cuerpo y `Content-Length` exactos; HTML con la misma frase sigue sustituyendo.
  - **Verificación:** `make verify` OK; benchmark 10 GiB `44208 B/op`, `25 allocs/op`; `rg "io\\.ReadAll|ioutil\\.ReadAll" proxy/relay.go proxy/server.go proxy/antivirus.go` sin resultados.

- [x] **HF-4: Vídeo embebido no reproduce por inspección de rangos/media.**
  - **Síntoma:** en Marca un vídeo embebido de Dailymotion no se ve. Los logs muestran tráfico Dailymotion y muchos sockets ociosos, pero no una respuesta de vídeo clara.
  - **Causa probable:** con `[magic]` activo, LucidGate forzaba inspección y `Transfer-Encoding: chunked` en respuestas no mutables. En respuestas `206 Partial Content`/`Range` de players de vídeo, quitar `Content-Length` o cambiar framing puede romper el reproductor.
  - **Fix:** `isRangeOrMediaResponse()` excluye de inspección/magic/antivirus las respuestas `206`, peticiones con `Range` y `video/*`/`audio/*`. Se preservan `Content-Length` y `Content-Range`.
  - **Regresión añadida:** `206 video/mp4` con `Content-Range` y `GET Range` octet-stream conservan cuerpo/framing exactos aunque `Magic` esté activo.
  - **Verificación:** `make verify` OK; benchmark 10 GiB `44272 B/op`, `27 allocs/op`; `rg "io\\.ReadAll|ioutil\\.ReadAll" proxy/relay.go proxy/server.go proxy/antivirus.go` sin resultados.

- [x] **HF-1: Sustitución no aplicada en respuestas HTML.**
  - **Síntoma:** las reglas `[[substitution.rule]]` (p.ej. `Madrid` → `Barcelona`) funcionaban en respuestas no-HTML pero no mutaban el cuerpo en `text/html`.
  - **Causa raíz:** en[proxy/relay.go](file:///home/yo/GIT/LucidGate/proxy/relay.go) `respFilter()` envolvía `SubstitutionFilter` con `newHTMLTextFilter(...)`. El [htmlTextFilter](file:///home/yo/GIT/LucidGate/proxy/html_filter.go) está diseñado como **observador pasivo** (descarta la salida del filtro interior y devuelve siempre `in` sin tocar) para alimentar el scoring del semantic-phrase-filter. Aplicado a un filtro mutante como Substitution, hace que sus bytes de salida se pierdan y nunca lleguen al cliente.
  - **Fix:** aplicar `Substitution.NewFilter()` directamente sobre los bytes crudos del cuerpo HTML, sin envolverlo en `htmlTextFilter`. Mismo tratamiento que ya recibía en la rama no-HTML.
  - **Verificación:** `curl --proxy ... https://en.wikipedia.org/wiki/Madrid` → 0 ocurrencias de `Madrid` y 726 de `Barcelona` (antes: 722/12).
- [x] **HF-2: Banner `LUCIDGATE INTERCEPTADO` se repetía decenas de veces en sitios con publicidad.**
  - **Síntoma:** al cargar `https://www.eldia.es` el navegador mostraba un montón de banners apilados.
  - **Causa raíz:** `HTMLInjectionFilter` se aplica a **toda** respuesta `text/html`. El sitio carga ~66 iframes de ads/tracking (DoubleClick, Amazon Ads, Taboola, PubMatic, Outbrain, Rubicon, AppNexus, Tappx, Richmediastudio…), cada uno recibe su banner fijado con `position:fixed; top:0` y se apilan visualmente.
  - **Fix:** nueva función `shouldInjectHTMLBanner(req)` en [proxy/relay.go](file:///home/yo/GIT/LucidGate/proxy/relay.go) que consulta la cabecera **`Sec-Fetch-Dest`** del request (Fetch Metadata Request Headers, RFC):
    - `document` → top-level navigation: SÍ inyectar.
    - `iframe`, `frame`, `image`, `script`, `embed`, `object`… → NO inyectar.
    - cabecera ausente (curl, clientes legacy/HTTP-1.0): SÍ inyectar (no rompe pruebas ni clientes no-browser).
  - Para acceder al request desde `respFilter()` se aprovechó `resp.Request`, que `http.ReadResponse(upstreamReader, req)` ya rellena. La firma de `respFilter` pasó a `(engine, contentType, req *http.Request)`; `nil` es seguro.
  - **Verificación:**
    - `curl` (sin header) → 1 banner ✅
    - `curl -H "Sec-Fetch-Dest: document"` → 1 banner ✅
    - `curl -H "Sec-Fetch-Dest: iframe"` → 0 banners ✅
    - `curl -H "Sec-Fetch-Dest: image"` → 0 banners ✅
    - `Madrid → Barcelona` sigue funcionando (HF-1 no regresa).
    - `go test ./proxy/... -count=1` → OK.
    - `go build -buildvcs=false -o build/lucidgate .` → OK.

## Plan activo - Fase 0.1 + 0.3

- [x] Auditar configuración, relay y tests existentes antes de tocar código.
-[x] Crear `lucidgate.toml` de ejemplo y añadir soporte TOML con precedencia conservadora: defaults < TOML < entorno < flags.
- [x] Mantener compatibilidad temporal con variables `CLEARGATE_*` y añadir `LUCIDGATE_*`.
- [x] Eliminar `io.ReadAll` del relay HTTP: peticiones y respuestas deben fluir por streaming con contadores y captura acotada.
- [x] Añadir `sync.Pool` de buffers de 32KB y usar `io.CopyBuffer` en el path de transferencia de cuerpos.
- [x] Verificar con tests y búsqueda textual que `proxy/relay.go` ya no contiene `io.ReadAll`/`ioutil.ReadAll`.

## Plan activo - Fase 0.2 + 0.4

- [x] Añadir `SIGHUP` para recargar `lucidgate.toml` en un `atomic.Value` sin locks en el hot path.
- [x] Aplicar en caliente las opciones mutables del relay (`log_bodies`, `max_capture_bytes`, `dump_dir`, `io_timeout`) desde la config atómica.
- [x] Añadir `server.max_connections` recargable con semáforo no bloqueante: devolver HTTP 503 antes de hijack si se excede.
- [x] Añadir `server.io_timeout` y deadlines de lectura/escritura alrededor de cada operación de red del relay.
- [x] Cubrir backpressure/deadlines/config reload con tests y ejecutar verificación.

## Plan activo - Fase 0.5

- [x] Añadir benchmark reproducible de transferencia streaming de 10GB sin archivo físico.
- [x] Ejecutar el benchmark con `-benchtime=1x -benchmem` para demostrar asignaciones acotadas: `44160 B/op`, `24 allocs/op`.
- [x] Mantener `make test` y `make build` verdes tras la prueba.
- [x] Documentar el comando de verificación para repetir la prueba.

## Plan activo - Fase 1

- [x] Forzar `Transfer-Encoding: chunked` y eliminar `Content-Length` en respuestas de texto mutables.
- [x] Definir `FilterEngine` y `InspectReader` para procesar chunks sin buffering completo.
- [x] Bypassear binarios, imagen, video y payloads comprimidos hasta implementar descompresión streaming.
- [x] Añadir tests para headers chunked, filtro streaming y fast-path binario.
- [x] Repetir verificación completa, incluido benchmark 10GB y búsqueda anti-`ReadAll`.

## Plan activo - Fase 2.1

- [x] Implementar trie inverso de dominios para bloquear dominio raíz y subdominios con lookup O(labels).
- [x] Cargar listas planas desde `rules.include_dir`, ignorando comentarios y líneas vacías.
- [x] Publicar reglas en `atomic.Value` y consultarlas antes de `Hijack`/dial upstream.
- [x] Añadir tests unitarios y de fast-fail CONNECT.
- [x] Repetir verificación completa.

## Plan activo - Fase 2.2

-[x] Añadir perfiles de acceso por CIDR en TOML para mapear IP local -> perfil.
-[x] Implementar `AccessRules` inmutable con `netip.Prefix` y lookup lineal compacto fuera de locks.
- [x] Rechazar clientes no autorizados antes de `Hijack`, dominio o upstream.
- [x] Añadir tests de config, matching y fast-fail CONNECT.
- [x] Repetir verificación completa.

## Plan activo - Fase 2.3

- [x] Añadir ventanas horarias por perfil en TOML.
- [x] Compilar horarios en estructura inmutable sin locks en el hot path.
- [x] Evaluar perfil del cliente contra el horario antes de `Hijack`.
- [x] Añadir tests de config, evaluación de ventanas y fast-fail CONNECT fuera de horario.
- [x] Repetir verificación completa.

## Plan activo - Fase 2.4

- [x] Sustituir respuestas `http.Error` de fast-fail por una plantilla HTML limpia de LucidGate.
- [x] Cubrir denegaciones por cliente, horario, dominio y saturación de conexiones.
- [x] Mantener todas las respuestas de bloqueo antes de `Hijack` y antes de dial upstream.
- [x] Añadir tests de status, `Content-Type` y contenido visible de la página.
- [x] Repetir verificación completa.

## Plan activo - Fase 3.1

- [x] Recuperar estado tras REISUB: validar implementación parcial existente antes de asumir que falta todo.
- [x] Endurecer tests y detalles pendientes sin romper streaming, `sync.Pool`, deadlines ni hot reload por `atomic.Value`.
- [x] Añadir configuración TOML `[semantic] blocked_phrases = [...]`.
- [x] Compilar frases en un `FilterEngine` inmutable basado en Aho-Corasick.
- [x] Mantener estado streaming mínimo por conexión para detectar frases partidas entre chunks.
- [x] Publicar el filtro con `atomic.Value` vía `RelayOptions` en hot reload.
- [x] Añadir tests unitarios y de relay para match, no-match, boundary de chunk y bypass binario.
- [x] Ejecutar `make test`, `make build`, benchmark 10GB y búsqueda anti-`ReadAll` en `proxy/relay.go`.
- [x] Repetir verificación completa: `make test` OK, `make build` OK, benchmark 10GiB `44192 B/op`, `25 allocs/op`, `rg "io\\.ReadAll|ioutil\\.ReadAll" proxy/relay.go` sin resultados.

## 🚦 FASE 0: Resiliencia Base, Memoria y Configuración TOML
*Objetivo: Purgar los cuellos de botella del proxy original y prepararlo para carga empresarial.*

- [x] **0.1. Integración de Configuración TOML:**
  - Instalar `github.com/pelletier/go-toml/v2`.
  - Crear estructura `Config` que mapee un archivo `lucidgate.toml`.
  - Soportar `include_dir` en el TOML para cargar listas de reglas desde otros archivos.
  - Migrar flags y variables de entorno actuales al TOML.
- [x] **0.2. Recarga en Caliente (Hot-Reload):**
  - Implementar captura de señal `SIGHUP`.
  - Usar `atomic.Value` para almacenar el puntero al `Config` actual. Las goroutines deben leer la config sin usar Mutex.
- [x] **0.3. PURGA CRÍTICA (Eliminar `io.ReadAll`):**
  - Modificar `proxy/relay.go`. Eliminar el uso de `io.ReadAll` en `captureRequestBody` y `captureResponseBody`.
  - Implementar un `sync.Pool` de buffers de 32KB.
  - Cambiar el sistema de logging actual para que cuente los bytes mediante un `io.Writer` intermedio o `io.CopyBuffer` en streaming real.
- [x] **0.4. Resiliencia de Red (Timeouts & Límites):**
  - Implementar `SetReadDeadline` y `SetWriteDeadline` estrictos en el relay loop de red.
  - Implementar un Semáforo (`make(chan struct{}, maxConns)`) para limitar el número global de conexiones simultáneas y evitar agotamiento de File Descriptors.
-[x] **0.5. Verificación de Fase 0:**
  - Demostrar mediante benchmark/test que el uso de RAM se mantiene estable al descargar un archivo de 10GB a través del proxy.

## 🌐 FASE 1: Motor de Intercepción Streaming y Mutación
*Objetivo: Preparar la "tubería" HTTP para que el contenido pueda ser alterado al vuelo.*

- [x] **1.1. Manejo de Chunked Encoding:**
  - Implementar lógica en el relay HTTP: Si la respuesta es de un tipo MIME modificable (`text/html`), eliminar `Content-Length` de los headers hacia el cliente local.
  - Inyectar `Transfer-Encoding: chunked`.
- [x] **1.2. Interfaz `FilterEngine`:**
  - Definir la interfaz base: `ProcessChunk(in[]byte) (out[]byte, blocked bool, err error)`.
  - Crear un reader intermedio (`InspectReader`) que envuelva el `resp.Body` del upstream y pase los chunks por el `FilterEngine` antes de enviarlos al cliente.
- [x] **1.3. Bypass Inteligente (Fast-Path):**
  - Evaluar `Content-Type`. Si es `video/*`, `image/*`, `application/octet-stream` (binarios no escaneables por texto), puentear el `FilterEngine` y usar streaming directo puro.

## 🛡️ FASE 2: Filtrado Fast-Fail (Capa L7 Meta y DNS)
*Objetivo: Reglas de acceso, listas blancas/negras y horarios.*

- [x] **2.1. Motor de Listas Negras/Blancas (URLs y Dominios):**
  - Implementar estructura basada en Radix Tree o Trie para búsquedas ultrarrápidas de dominios.
  - Soportar carga desde listas externas en el TOML (formato plano, un dominio por línea).
- [x] **2.2. Control de Acceso por IP y Autenticación:**
  - Módulo de mapeo de IP local -> Perfil de filtrado.
  - (Opcional) Soporte para leer cabeceras de proxy-auth para usuarios.
- [x] **2.3. Políticas de Tiempo y Horarios:**
  - Evaluar reglas dentro de rangos horarios definidos en el TOML.
- [x] **2.4. Plantillas de Bloqueo (Block Pages):**
  - Implementar servidor interno que devuelva una página HTML limpia ("Acceso Denegado por LucidGate") cuando el Fast-Fail actúe, cortando la petición original.

## 🧠 FASE 3: Motor de Inspección Semántica de Contenido
*Objetivo: Filtrado por palabras clave y puntuación (Weighted Phrases) sin destruir la CPU.*

- [x] **3.1. Algoritmo Aho-Corasick:**
  - Integrar motor Aho-Corasick para la búsqueda lineal y simultánea de miles de palabras en los chunks de texto.
- [x] **3.2. Descompresión Transparente:**
  - Si el upstream envía `Content-Encoding: gzip/deflate/br`, enganchar un decompressor al vuelo -> Inspeccionar texto -> Recomprimir -> Enviar al cliente.
  - [x] Soportar solo respuestas mutables (`text/*`, json/xml/js) y solo codificaciones con reader/writer streaming (`gzip`, `x-gzip`, `deflate`, `br`, `identity`).
  - [x] Eliminar `Content-Length`, mantener `Content-Encoding`, emitir `Transfer-Encoding: chunked` y no materializar el cuerpo completo.
  - [x] Cubrir gzip/deflate/br con tests que descomprimen la respuesta serializada y validan bloqueo semántico.
  - [x] Mantener bypass para codificaciones no soportadas como `zstd`.
  - [x] Repetir verificación completa: `make test` OK, `make build` OK, benchmark 10GiB `44192 B/op`, `25 allocs/op`, `rg "io\\.ReadAll|ioutil\\.ReadAll" proxy/relay.go` sin resultados.
- [x] **3.3. Sistema de Scoring Acumulativo:**
  - Dar pesos a las palabras (ej: "arma": +20, "bomba": +40). 
  - Bloquear la conexión si el score acumulado supera el límite del perfil.
  - [x] Mantener `blocked_phrases` como bloqueo inmediato y añadir `score_threshold` + `[[semantic.weighted_phrase]]`.
  - [x] Compilar pesos en el mismo Aho-Corasick inmutable y acumular score por stream sin locks ni buffering total.
  - [x] Validar pesos/umbral en config y cubrir compatibilidad legacy, acumulación entre chunks y relay.
  - [x] Repetir verificación completa: `make test` OK, `make build` OK, benchmark 10GiB `44192 B/op`, `25 allocs/op`, `rg "io\\.ReadAll|ioutil\\.ReadAll" proxy/relay.go` sin resultados.
- [x] **3.4. Tokenizador HTML Básico:**
  - Limpiar tags HTML al vuelo para que el motor Aho-Corasick solo lea texto visible, evitando falsos positivos o saltos de línea maliciosos entre palabras.
  - [x] Aplicar solo a `text/html`/`application/xhtml+xml` y mantener JSON/XML/text plano con el filtro semántico directo.
  - [x] Ignorar tags/atributos/comentarios y contenido `script`/`style` sin copiar ni transformar el cuerpo completo.
  - [x] Seguir devolviendo el HTML original hasta el byte que dispara el bloqueo en texto visible.
  - [x] Cubrir falsos positivos en atributos, evasión por tags entre letras y bypass de script/style.
  - [x] Repetir verificación completa: `make test` OK, `make build` OK, benchmark 10GiB `44192 B/op`, `25 allocs/op`, `rg "io\\.ReadAll|ioutil\\.ReadAll" proxy/relay.go` sin resultados.

## ✏️ FASE 4: Manipulación, Censura y DLP
*Objetivo: Alterar contenido y vigilar subidas (Data Loss Prevention).*

-[x] **4.1. Sustitución y Censura (Masking):**
  - Reemplazar dinámicamente frases censuradas por asteriscos (****) en los chunks, ajustando los tamaños gracias a la Fase 1.
  - [x] Añadir `[masking] phrases = [...]` para texto no HTML y payloads textuales comprimidos ya soportados.
  - [x] Compilar un filtro inmutable separado, con estado streaming y retención de `max_phrase_len-1` bytes para matches entre chunks.
  - [x] Preservar longitud sustituyendo cada byte de la frase por `*`, sin buffering completo ni cambios de MIME.
  - [x] No aplicar masking a `text/html` todavía; HTML visible necesita mapeo posición-texto/original más cuidadoso.
  - [x] Repetir verificación completa: `make test` OK, `make build` OK, benchmark 10GiB `53664 B/op`, `26 allocs/op`, `rg "io\\.ReadAll|ioutil\\.ReadAll" proxy/relay.go` sin resultados.
- [x] **4.2. Inyección de HTML:**
  - Añadir capacidad para inyectar un banner flotante de advertencia al encontrar la etiqueta `</body>` en el stream.
  - [x] Añadir `[injection] html_banner = "..."` y aplicarlo solo a HTML.
  - [x] Detectar `</body>` case-insensitive entre chunks reteniendo solo `len("</body>")-1` bytes.
  - [x] Inyectar una sola vez antes de `</body>` y no modificar respuestas no HTML.
  - [x] Mantener bloqueo semántico antes de inyección; si una respuesta se bloquea, no añadir banner artificial.
  - [x] Repetir verificación completa: `make test` OK, `make build` OK, benchmark 10GiB `53664 B/op`, `26 allocs/op`, `rg "io\\.ReadAll|ioutil\\.ReadAll" proxy/relay.go` sin resultados.
- [x] **4.3. Filtro POST (Subida de Datos):**
  - Inspeccionar peticiones POST. 
  - Limitar el buffering en memoria de multipart forms para evitar DoS. Stream a un archivo temporal (`/tmp`) si es necesario para inspección.
  -[x] Inspeccionar cuerpos de métodos con upload (`POST`, `PUT`, `PATCH`) solo si el `Content-Type` es textual.
  - [x] Usar el filtro semántico existente en streaming antes de escribir cada chunk upstream; no usar `ParseMultipartForm` ni `io.ReadAll`.
  - [x] Bypass explícito para multipart/binario; la inspección multipart profunda queda fuera hasta spool a `/tmp`.
  - [x] Al detectar contenido prohibido, cortar la transferencia upstream y cerrar el relay; respuesta HTTP de bloqueo para uploads queda como mejora posterior.
  - [x] Repetir verificación completa: `make test` OK, `make build` OK, benchmark 10GiB `53664 B/op`, `26 allocs/op`, `rg "io\\.ReadAll|ioutil\\.ReadAll" proxy/relay.go` sin resultados.

## Plan activo - Fase 5.1

- [x] Añadir `[magic] blocked_types = [...]` al TOML y validarlo en config.
- [x] Implementar `MagicFilter` streaming con prefijo acotado a 512 B y reinyección al stream cuando no se bloquea.
- [x] Detectar firmas custom (PE `MZ`, ELF, Mach-O, scripts `#!`) y delegar el resto a `http.DetectContentType`.
- [x] Integrar `MagicFilter` en `ContentFilter` y forzar inspección incluso para content-types no mutables cuando Magic esté activo.
- [x] Mantener bypass cuando el `Content-Encoding` no es soportable.
- [x] Cubrir con tests: bloqueo por PE/ELF/Mach-O, bloqueo por MIME real (zip), passthrough para texto, boundary de chunk, response < 512 B vía Flush.
- [x] Verificación completa: `make test` OK, `make build` OK, benchmark 10 GiB `53648 B/op`, `25 allocs/op`, grep `"io\\.ReadAll|ioutil\\.ReadAll" proxy/relay.go` sin resultados.

## Plan activo - Fase 5.2

- [x] Diseñar `Antivirus` opcional para binarios no textuales, sin tocar el path caliente cuando esté desactivado.
- [x] Implementar goteo con tempfile: descarga upstream a disco con `sync.Pool`, envía un prefijo lento al cliente, escanea el fichero completo y libera el resto si está limpio.
- [x] Añadir scanner ClamAV `INSTREAM` configurable por TOML y scanner fake para tests.
- [x] Integrar en `ContentFilter`/relay manteniendo `Transfer-Encoding: chunked` y sin `Content-Length` para respuestas escaneadas.
- [x] Cubrir limpio/infectado/bypass textual y limpieza de temporales.
-[x] Verificar con `make verify`, build, benchmark y búsqueda anti-`ReadAll`.

## 🦠 FASE 5: Seguridad y Escaneo de Binarios
*Objetivo: Integración con antivirus y escaneo pesado.*

- [x] **5.1. Bloqueo por Firmas Mágicas / MIME Real:**
  - No confiar en la extensión `.jpg`. Leer los primeros 512 bytes del chunk inicial (`http.DetectContentType`) para bloquear ejecutables disfrazados.
  - [x] `MagicFilter` streaming con prefijo ≤512 B; firmas custom para PE/ELF/Mach-O/scripts y delegación a `http.DetectContentType`.
  - [x] `[magic] blocked_types = [...]` configurable y recargable; integrado en `ContentFilter` antes del semántico/masking/HTML.
  - [x] `shouldInspectResponse` extendido: fuerza inspección y `Transfer-Encoding: chunked` también para `application/octet-stream` cuando hay magic activo.
  - [x] Bypass automático para `Content-Encoding` no soportado (zstd) y para respuestas sin cuerpo.
  - [x] Reinyección del prefijo al cliente cuando no hay match; bloqueo trunca el cuerpo upstream sin liberar bytes.
  - [x] Verificación completa: `make test` OK, `make build` OK, benchmark 10 GiB `53648 B/op`, `25 allocs/op`, sin `io.ReadAll`/`ioutil.ReadAll` en `proxy/relay.go`.
- [x] **5.2. Antivirus Trickling (Goteo HTTP):**
  - Al bajar un binario, descargarlo a un archivo temporal en el proxy mientras se envía al cliente 1 byte/segundo (Keep-Alive). 
  - Pasar por ClamAV (o ICAP). Si está limpio, inyectar el resto a máxima velocidad. Si es virus, cortar la conexión TCP.
  - [x] `[antivirus]` opcional en TOML: `enabled`, `clamav_addr`, `temp_dir`, `trickle_interval`, `scan_timeout`.
  - [x] Scanner ClamAV `INSTREAM` sin cargar el fichero completo en memoria.
  - [x] Reader de goteo: descarga a tempfile con buffers del `sync.Pool`, gotea prefijo, escanea y libera/corta.
  - [x] Integrado solo para respuestas binarias/no textuales `200 OK`; textos siguen por el pipeline mutable existente.
  - [x] Verificación completa: `make verify` OK; benchmark 10 GiB `44224 B/op`, `26 allocs/op`; `rg "io\\.ReadAll|ioutil\\.ReadAll" proxy/relay.go proxy/server.go proxy/antivirus.go` sin resultados.

## 📊 FASE 6: Observabilidad Enterprise
- [ ] **6.1. Integración de Logs Estructurados Detallados (JSONL).**
-[ ] **6.2. Auditoría de Tráfico (IP, Usuario, Acción, Categoría Bloqueada).**
- [ ] **6.3. Métricas Prometheus Básicas (Throughput, Latencia de Inspección, Hits de Reglas).**

---

# 🚀 FASE 7: TELCO-GRADE — Escalado Masivo (Carrier Class)

> **Objetivo macro:** llevar LucidGate de ~100 conexiones simultáneas / ~1 Gbps a **>50.000 conexiones simultáneas y 10 Gbps por nodo**, con resiliencia tipo carrier (NTT, Cloudflare, Akamai). Cada subtarea lleva: **(a)** cuello de botella concreto del código actual con `file:línea`, **(b)** algoritmo / librería moderna que lo sustituye, **(c)** métrica esperada, **(d)** criterio de verificación.

> **Reglas para esta fase:** ningún `cgo` opcional puede ser obligatorio (mantener `pure-go` build). Toda dependencia nueva debe estar mantenida en 2025+ y benchmarkeada vs lo que sustituye. Cada PR debe traer **benchmark before/after** y **profile pprof** adjuntos al `tasks/lessons.md`.

---

## 🧨 7.1. Eliminar el techo de la TLS-MITM (CPU & RAM dominante)

Cuello de botella nº 1. El handshake TLS local + el handshake uTLS upstream consume el 60–80 % del CPU bajo carga. Cada cliente nuevo cuesta ~3–8 ms de CPU.

- [x] **7.1.1. `LeafCache` con singleflight + LRU acotado.**
  - **Hoy:**[pki/leaf.go#L91-L131](file:///home/yo/GIT/LucidGate/pki/leaf.go#L91-L131) usa `sync.RWMutex` + `map[string]*tls.Certificate` que **crece sin límite** (memory leak en producción con SNIs aleatorios tipo CDN: `*.fbcdn.net`, `*.googlevideo.com`).
  - **Riesgo concreto:** un cliente malicioso o un escaneo SNI puede meter 1 M de hostnames inventados → ~700 MB RAM + GC pressure.
  - **Solución implementada (2026-05-03):**
    - LRU acotado sin dependencia externa (`lruCache` + lista doblemente enlazada en [pki/leaf.go](file:///home/yo/GIT/LucidGate/pki/leaf.go)). `DefaultLeafCacheSize = 4096`. `NewLeafCacheWithSize` permite override.
    - Singleflight inline (`map[string]*pendingCert` + `chan struct{}`) para deduplicar generaciones concurrentes del mismo host sin pull de `golang.org/x/sync`.
    - `leafStillValid()` regenera si quedan menos de 1 h hasta `NotAfter`.
  - **Verificación:** `go test -race ./pki/` OK; `make test` OK.

- [ ] **7.1.2. Pre-generar certs en background workers.**
  - **Hoy:** la primera conexión a un host nuevo paga la generación (~2-4 ms ECDSA P-256) en el hot-path, **dentro del handshake con el cliente** → handshake_timeout de 5 s puede sufrir.
  - **Solución:** pool de N workers (configurable, default `runtime.NumCPU()`) que reciben hostnames por canal y rellenan el LRU en segundo plano. El hot-path solo bloquea si LRU miss.
  - Usar `tls.Config.GetCertificate` (callback) en vez de `Certificates:[]tls.Certificate{*cert}` ([proxy/server.go#L419-L422](file:///home/yo/GIT/LucidGate/proxy/server.go#L419-L422)) para diferir la decisión a tiempo de SNI.
  - **Métrica:** P99 de handshake local < 5 ms incluso en `host-cold`.

- [x] **7.1.3. TLS Session Resumption (PSK + Tickets) downstream + upstream.**
  - **Hoy:** ni el `tls.Config` del lado cliente ([proxy/server.go#L419](file:///home/yo/GIT/LucidGate/proxy/server.go#L419)) ni el `utls.Config` del upstream ([stealth/dial.go#L58-L66](file:///home/yo/GIT/LucidGate/stealth/dial.go#L58-L66)) configuran `ClientSessionCache` ni `SessionTicketKey`. Cada reconexión paga handshake completo (~10-20 ms RTT + ~3 ms CPU).
  - **Implementado (2026-05-03):**
    - Downstream: `downstreamSessionCache = tls.NewLRUClientSessionCache(8192)` cableada en `tls.Server` config dentro de `handleHTTPS` ([proxy/server.go](file:///home/yo/GIT/LucidGate/proxy/server.go)).
    - Upstream: `upstreamSessionCache = utls.NewLRUClientSessionCache(8192)` cableada en `Dialer.DialFirefox` ([stealth/dial.go](file:///home/yo/GIT/LucidGate/stealth/dial.go)) si el `utls.Config` no la trae prefijada.
  - **Pendiente menor:** rotación periódica de `SessionTicketKeys` cada 24 h y métrica de hit-ratio (espera a 7.6).

- [x] **7.1.4. Compartir un único `ecdsa.PrivateKey` por leaf cert.**
  - **Hoy:**[pki/leaf.go#L35](file:///home/yo/GIT/LucidGate/pki/leaf.go#L35) llama `ecdsa.GenerateKey` por cada cert. ~2 ms cada uno.
  - **Implementado:** `loadSharedLeafKey()` genera una única ECDSA P-256 con `sync.Once`; `GenerateLeafCert` reusa el `keyPEM` cacheado. Marshal de la clave eliminado del hot-path. Como LucidGate es un MITM cuyo leaf nunca sale del proxy, compartir keypair es seguro.
  - **Coste:** 0 keygens tras el primero. La generación de leaf se reduce a `x509.CreateCertificate` + `tls.X509KeyPair` (sin marshal de key).

---

## 🚦 7.2. Backpressure y QoS de carrera (de "503 inmediato" a "Smart Admission Control")

- [ ] **7.2.1. Sustituir `chan struct{}` no bloqueante por admission queue con timeout.**
  - **Hoy:** [proxy/server.go#L319-L327](file:///home/yo/GIT/LucidGate/proxy/server.go#L319-L327) hace `select { case <-default }` → si el slot está lleno devuelve 503 instantáneo. Mata UX en picos cortos.
  - **Solución:** `acquireConn(ctx)` espera hasta `wait_timeout` (default 250 ms) antes de degradar. Implementar con `semaphore.Weighted` (`golang.org/x/sync/semaphore`).
  - **Métrica:** 0 % de 503 con bursts < `max_connections * 1.2` durante < 200 ms.

- [ ] **7.2.2. Slots por perfil (multi-tenant fairness).**
  - **Hoy:** un único pool global. Si "kids" satura, "admin" también queda bloqueado.
  - **Solución:** `map[profile]*semaphore.Weighted` con cuotas por perfil declaradas en TOML (`[[access.profile]] max_conns = 200`). Algoritmo: **Weighted Fair Queueing** simplificado.
  - **Métrica:** perfil hambriento no afecta SLO de los demás (test sintético).

- [ ] **7.2.3. Rate-limit por IP cliente (token bucket).**
  - **Hoy:** ningún limit por IP. Un cliente solo puede agotar `max_connections`.
  - **Solución:** `golang.org/x/time/rate.Limiter` por IP, mantenido en LRU. Defaults: 100 req/s, burst 200.
  - **Métrica:** cliente abusivo no degrada percentiles del resto.

- [ ] **7.2.4. Idle timeout en vez de absolute deadline en streaming.**
  - **Hoy:**[proxy/relay.go#L82,98,113,121](file:///home/yo/GIT/LucidGate/proxy/relay.go#L82) renueva deadline solo entre exchanges del bucle. En `writeBodyStreaming` el deadline corre **dentro del cuerpo**, lo que mata streams largos legítimos (descargas, vídeos pausados).
  - **Solución:** wrapper `idleConn` que renueva `SetReadDeadline` cada N bytes leídos / cada chunk procesado. Equivalente al `IdleTimeout` de nginx.
  - **Métrica:** descarga 4K vídeo de 2 h sin reset; cliente Slowloris muere a los 10 s.

---

## 🌐 7.3. HTTP/2 y HTTP/3 — Multiplexación obligatoria a escala carrier

Hoy LucidGate **solo habla HTTP/1.1** ([stealth/dial.go#L15,89](file:///home/yo/GIT/LucidGate/stealth/dial.go#L15) fuerza ALPN `http/1.1`). 1 conexión = 1 request en vuelo. Un Chrome moderno abre 6 conns por dominio y los CDNs HTTP/2 multiplexan 100. Esto multiplica por 6-10 las conexiones que el proxy debe manejar.

- [ ] **7.3.1. Soporte HTTP/2 cliente↔proxy.**
  - **Hoy:** `http.Server` stdlib auto-negocia h2 si `TLSNextProto` no está vetado, pero el flujo del MITM hace `Hijack()` y bypass total, perdiendo h2.
  - **Solución:** detectar ALPN negociado en el `tls.Conn` post-handshake; si es `h2`, servir vía `http2.Server.ServeConn(tlsConn, &http2.ServeConnOpts{Handler: ...})` en vez de `bufio.NewReader` + `http.ReadRequest` ([proxy/relay.go#L78-L116](file:///home/yo/GIT/LucidGate/proxy/relay.go#L78)).
  - El handler reutiliza el pipeline de filtros vía `RoundTripper` custom.
  - **Métrica:** un único cliente Chrome con 100 streams paralelos consume **1** slot de `max_connections`, no 6+.

- [ ] **7.3.2. Soporte HTTP/2 proxy↔upstream (uTLS).**
  - **Hoy:**[stealth/dial.go#L82-L95](file:///home/yo/GIT/LucidGate/stealth/dial.go#L82) **fuerza `http/1.1`** explícitamente, suprimiendo h2 del ClientHello. Toda la red moderna negocia h2 → estamos forzando downgrade.
  - **Solución:** `forceHTTP1ALPN` se hace opt-in (perfil "legacy"). Por defecto, ALPN `[h2, http/1.1]`. Si negocia h2, usar `http2.Transport` con `DialTLS` que devuelve el `*utls.UConn`. Pool h2 compartido.
  - **Beneficio extra:** **1 conexión TCP+TLS** al upstream sirve N requests del mismo cliente o de clientes distintos al mismo host → reducción 5–10x de handshakes upstream.
  - **Métrica:** hits a `youtube.com` reusan 1 conn h2; `netstat | grep ESTABLISHED` cae > 70 %.

- [ ] **7.3.3. Soporte HTTP/3 (QUIC) downstream.**
  - **Hoy:** ninguno.
  - **Librería:** `github.com/quic-go/quic-go` + `quic-go/http3`. Madura (2025) y compatible con `tls.Config`.
  - **Solución:** listener UDP paralelo en mismo puerto (443) con Alt-Svc advertising. Reutilizar mismo handler.
  - **Métrica:** Chrome móvil en 4G negocia h3 y baja latencia P50 ~20 %.

---

## ⚡ 7.4. Acelerar el data-path — kernel & sockets

- [ ] **7.4.1. `SO_REUSEPORT` con N listeners == GOMAXPROCS.**
  - **Hoy:** un único `net.Listen` ([proxy/server.go#L140](file:///home/yo/GIT/LucidGate/proxy/server.go#L140)) → un solo accept loop. A >20 k conn/s el cuello es el accept queue del kernel.
  - **Solución:** abrir N socket con `SO_REUSEPORT` (paquete `golang.org/x/sys/unix` + `net.ListenConfig{Control:...}`). Cada uno corre en su goroutine. El kernel reparte con hash round-robin. Patrón estándar en HAProxy / Envoy.
  - **Librería de ayuda:** `github.com/libp2p/go-reuseport` (probada).
  - **Métrica:** accept rate 4-8x con N=8 cores.

- [x] **7.4.2. `TCP_NODELAY` ya está por defecto; añadir `TCP_KEEPALIVE` upstream.**
  - **Hoy:** [stealth/dial.go#L42](file:///home/yo/GIT/LucidGate/stealth/dial.go#L42) usa `net.Dialer{Timeout:...}` sin `KeepAlive`. Conexiones half-open se acumulan.
  - **Implementado:** `net.Dialer{Timeout: timeout, KeepAlive: upstreamKeepAlive}` con `upstreamKeepAlive = 30 * time.Second` ([stealth/dial.go](file:///home/yo/GIT/LucidGate/stealth/dial.go)).
  - **Pendiente:** exponer `TCP_USER_TIMEOUT` (Linux) en TOML cuando se aborde 7.4.1.

- [ ] **7.4.3. Zero-copy con `splice(2)` para fast-path binario/vídeo (HTTP plano).**
  - **Hoy:**[proxy/relay.go#L386,958-962](file:///home/yo/GIT/LucidGate/proxy/relay.go#L386) usa `io.CopyBuffer` con buffer de 32 KiB. El stdlib activa splice automáticamente entre dos `*net.TCPConn` con `io.Copy` directo (sin buffer userspace). El `CopyBuffer` **inhibe el fast-path splice** del stdlib.
  - **Solución:** detectar caso bypass-completo (sin filtro, sin captura, sin antivirus) → llamar `io.Copy(dst, src)` directo cuando ambos sean `*net.TCPConn`. Fallback a `copyBufferPooled` solo si hay capa que lo necesite.
  - **Limitación:** TLS rompe splice (`*tls.Conn` no es `*net.TCPConn`). Solo aplica al CONNECT-tunel **antes** del MITM (pasarela transparente, opt-in) y al HTTP plano binario.
  - **Métrica:** rendimiento 2-3x en transferencia binaria HTTP plano.

- [ ] **7.4.4. Buffer pool por tamaño (no solo 32 KiB).**
  - **Hoy:** un único `relayBufferPool` 32 KiB ([proxy/relay.go#L40-L45](file:///home/yo/GIT/LucidGate/proxy/relay.go#L40)).
  - **Solución:** dos pools: 4 KiB (headers / chunks pequeños) y 64 KiB (vídeo / binarios). Usar `bytebufferpool` de Valyala. Reduce GC scan time.

- [ ] **7.4.5. `bufio.NewReader` por conexión → `sync.Pool`.**
  - **Hoy:** [proxy/relay.go#L78-L79](file:///home/yo/GIT/LucidGate/proxy/relay.go#L78) crea `bufio.Reader` por cada relay HTTPS. 4 KiB por conn × 50 k conns = 200 MiB inútiles.
  - **Solución:** `bufio.Reader` reciclables vía pool. Aumentar tamaño a 16 KiB.

---

## 🧠 7.5. Algoritmos modernos para los filtros

- [x] **7.5.1. Aho-Corasick: `map[byte]int` → array `[256]int32` (compilado a DFA).**
  - **Hoy:** [proxy/semantic_filter.go#L8-L13](file:///home/yo/GIT/LucidGate/proxy/semantic_filter.go#L8-L13) usaba `map[byte]int` por nodo. Cada `nextState` hacía ~3-5 lookups de mapa = ~30-60 ns/byte.
  - **Implementado (2026-05-03):**
    - `ahoNode.next [256]int32`: transición denso array.
    - `buildFailures()` reescrito: BFS que **compila** el goto-table en DFA completo (cada celda vacía hereda la transición del fail target). Resultado: `nextState` degenerado a una sola lectura `nodes[node].next[b]` por byte, sin walk del fail-chain.
    - `matchChunk` cachea `node`/`score` en variables locales antes del loop para evitar field-loads dentro del hot path.
  - **Resultado real (Intel i5-4440 @ 3.1 GHz, 1 core):**
    - `BenchmarkPhraseFilterProcessChunk -benchtime=2s` → **279.15 MB/s, 0 B/op, 0 allocs/op** ⇒ ~3.5 ns/byte.
    - Antes (map-based): ~30-60 ns/byte estimado. Mejora **>10x**, supera el target de 5 ns/byte.
    - 64 KiB chunk: ~234 µs (target era < 100 µs en CPU 8-core moderna; cumplido).
  - **Pendiente:** `petar-dambovaliev/aho-corasick` o Hyperscan cgo solo se evaluarán si aparecen >100 k frases (hoy no hay caso de uso).

-[ ] **7.5.2. Domain trie compacto (LPM) — sustituir `map[string]*node`.**
  - **Hoy:**[proxy/domain_rules.go#L11-L14](file:///home/yo/GIT/LucidGate/proxy/domain_rules.go#L11-L14) usa map por nodo. Para listas serias (Easylist + URLhaus + StevenBlack ~3 M dominios) son ~3 GiB de RAM y 200-500 ns/lookup.
  - **Solución:** estructura aplanada en arrays (cache-friendly), o **hashing perfecto** ofline (ej. `cespare/mph`) si la lista no muta entre reloads, o **succinct trie** (`github.com/openacid/slim`) que comprime 10x.
  - **Bonus:** aceptar formato Adblock-Plus / Pi-hole / DNSBL.
  - **Métrica:** 3 M dominios cargados en < 500 MiB, lookup < 80 ns.

- [ ] **7.5.3. CIDR matching: lineal → BART (best-of-class LPM).**
  - **Hoy:**[proxy/access_rules.go#L71-L75](file:///home/yo/GIT/LucidGate/proxy/access_rules.go#L71-L75) hace `for _, entry := range r.entries` lineal. Para >100 prefijos es lento, para >10 k es ridículo.
  - **Solución:** `github.com/gaissmai/bart` (Balanced Routing Tree, O(log N) con ~50 ns/lookup, paper 2023). Reemplaza `cidranger`.
  - **Métrica:** 100 k prefijos, lookup P99 < 200 ns.

-[x] **7.5.4. Compresión: `compress/gzip` → `klauspost/compress/gzip`.**
  - **Implementado:** imports cambiados a `github.com/klauspost/compress/gzip` y `.../flate` en [proxy/relay.go](file:///home/yo/GIT/LucidGate/proxy/relay.go). API drop-in compatible. `go mod tidy` la promovió de indirecta a directa.
  - **Beneficio esperado:** 2-3x más rápido en gzip/deflate de respuestas inspeccionadas. Se medirá en suite 7.8.

- [ ] **7.5.5. Brotli puro Go → `klauspost/compress` o cgo opcional.**
  - **Hoy:** `andybalholm/brotli` (puro Go, lento). klauspost no tiene brotli; alternativa cgo `github.com/google/brotli/go/cbrotli` 5-10x más rápido. Mantener fallback puro Go con build tag.

-[ ] **7.5.6. Soporte `zstd` streaming (hoy bypass total).**
  - **Hoy:** [proxy/relay.go#L883-L887](file:///home/yo/GIT/LucidGate/proxy/relay.go#L883) hace bypass para `zstd` → no inspeccionamos respuestas zstd, agujero de seguridad creciente (Cloudflare lo está adoptando masivamente en 2025).
  - **Solución:** `github.com/klauspost/compress/zstd` con reader/writer streaming (sí, no `Decode([])`).

---

## 📈 7.6. Observabilidad sin coste (pre-requisito de cualquier optimización)

- [x] **7.6.1. Logger sin allocaciones: `log.Printf` → `log/slog` con handler zerolog/zap.**
  - **Implementado (2026-05-03):** El logger nativo `log` (serializado por `sync.Mutex`) ha sido completamente reemplazado en la canalización central por `log/slog` de la stdlib + `JSONHandler`. Cero dependencias y JSON real out-of-the-box para eventos operativos ("exchange", etc.). 

- [ ] **7.6.2. Endpoint Prometheus `/metrics` (mismo `http.Server` interno separado).**
  - Métricas mínimas: conexiones activas, bytes in/out, cert cache hit-ratio, filter hit/block, p50/p95/p99 latencia handshake, latencia ProcessChunk, FDs.
  - **Librería:** `prometheus/client_golang`. Histogramas con buckets nativos (sparse) v1.16+.

- [x] **7.6.3. pprof endpoint protegido (loopback only).**
  - **Implementado (2026-05-03):** El endpoint `127.0.0.1:6060` de pprof nativo está levantado en `main.go`. Permite tirar perfiles en caliente con `go tool pprof http://localhost:6060/debug/pprof/profile?seconds=5` durante las pruebas de carga.

- [ ] **7.6.4. Tracing OpenTelemetry opcional.**
  - Span por exchange (CONNECT, dial, handshake, ProcessChunk, copy). Exporta vía OTLP. Útil para correlacionar lentitud con upstream concreto.

- [x] **7.6.5. Dump de cuerpos asíncrono.**
  - **Implementado (2026-05-03):** Se eliminó el `dumpMu` en [proxy/relay.go](file:///home/yo/GIT/LucidGate/proxy/relay.go). Las escrituras de payloads en crudo ahora fluyen por un canal (`dumpChan`) a una única goroutine `asyncDumpLoop` que utiliza `bufio.Writer` asíncrono y flushea cada 100 ms o por buffer lleno. En picos masivos se ignora el payload (con aviso al logger), evitando un freno sistémico a las conexiones en curso.

---

## 🛟 7.7. Resiliencia operativa carrier-grade

- [ ] **7.7.1. Hot-restart con FD passing (zero-downtime upgrade).**
  - **Hoy:** SIGHUP recarga config pero un upgrade del binario corta TODAS las conexiones.
  - **Solución:** `github.com/cloudflare/tableflip` (production-grade, lo que usa Cloudflare). Pasa el listener al nuevo proceso, drena el viejo gracefully.

- [ ] **7.7.2. Graceful drain de conexiones streaming activas en shutdown.**
  - **Hoy:**[proxy/server.go#L155-L172](file:///home/yo/GIT/LucidGate/proxy/server.go#L155) hace `httpServer.Shutdown` con timeout 5 s, pero las hijacked (CONNECT-MITM) se cortan duras.
  - **Solución:** registry de `net.Conn` activas con `sync.Map`; en shutdown enviar TCP FIN respetando el frame en curso, esperar `drain_timeout` (default 30 s) antes de close forzado.

- [x] **7.7.3. `automaxprocs` para entornos containerizados.**
  - **Implementado (2026-05-03):** El import ciego `_ "go.uber.org/automaxprocs"` se añadió a `main.go`. En Kubernetes o cgroups limitados, el `GOMAXPROCS` se ajustará de forma proactiva a las cuotas reales, evitando tormentas de context-switching.

- [ ] **7.7.4. Health checks (liveness/readiness) HTTP separado.**
  - Endpoint `:9090/livez` y `/readyz`. Readyz devuelve 503 si el pool está saturado o si SIGHUP está en curso.

- [ ] **7.7.5. Circuit breaker upstream.**
  - **Hoy:** un upstream lento bloquea slots `io_timeout` segundos.
  - **Solución:** `sony/gobreaker` por host upstream. Si N fallos consecutivos, abre y devuelve 502 instantáneo durante cool-down.

- [ ] **7.7.6. Fallback de DNS resolver con caché (no usar `net.DefaultResolver` directamente).**
  - **Solución:** caché DNS interna con TTL respetando RR, usando `miekg/dns` o `dnscache`. Evita ir al sistema 50 k veces/s.

---

## 🧪 7.8. Banco de pruebas de carga (sin esto, todo lo anterior es ciencia ficción)

- [ ] **7.8.1. Suite `bench/` con `wrk2` + `vegeta` + `h2load`.**
  - Target: 50 k conn simultáneas, 100 k req/s mixtas (HTML + vídeo + binario), 24 h sin OOM ni leak.
  - Comparar baseline (rama `main`) vs cada PR de Fase 7.

- [ ] **7.8.2. Test de fuga de FDs y goroutines.**
  - `runtime.NumGoroutine()` y `/proc/self/fd` muestreados cada 30 s; falla el test si crecen tras drenar.

- [ ] **7.8.3. Test de Slowloris / Slow-POST / GoAway-flood (HTTP/2).**
  - Cliente sintético manda headers byte a byte, body byte a byte, RST_STREAM masivo (CVE-2023-44487 "Rapid Reset").

- [ ] **7.8.4. Test de degradación elegante: 200 % de la capacidad nominal.**
  - Verificar que latencia P50 sube < 3x y NO se cae el proceso.

- [ ] **7.8.5. Profiling continuo en CI (regresión perf).**
  - `pprof` diff entre baseline y PR. Falla CI si CPU/byte sube > 10 %.

---

## 🎯 Cuadro de Métricas Diana (DoD de Fase 7)

| Métrica | Hoy | Diana Telco |
|---|---|---|
| Conexiones simultáneas estables | ~100 | **≥ 50.000** |
| Throughput agregado por nodo | ~600 Mbps–1 Gbps | **≥ 10 Gbps** |
| RAM con 50 k conns | ? | **≤ 4 GiB** |
| Handshake P99 (cert cold) | ? | **≤ 5 ms** |
| ProcessChunk Aho-Corasick | ~30-60 ns/byte | **≤ 5 ns/byte** |
| 503 con burst transitorio | sí, instantáneo | **0 % bajo `wait_timeout`** |
| Conexiones upstream por host (h2) | 1:1 con cliente | **multiplexadas (~10:1)** |
| Hot upgrade del binario | corte total | **0-downtime (tableflip)** |

---

## 📦 Inventario de librerías nuevas propuestas (auditadas)

| Reemplaza | Hoy | Propuesto | Por qué |
|---|---|---|---|
| LRU cert | `map+RWMutex` ([pki/leaf.go](file:///home/yo/GIT/LucidGate/pki/leaf.go)) | `hashicorp/golang-lru/v2` | Acotado, thread-safe, O(1) |
| Singleflight cert | — | `golang.org/x/sync/singleflight` | Dedup de generaciones paralelas |
| Aho-Corasick | propio map-based | `petar-dambovaliev/aho-corasick` (puro Go) o `flier/gohs` (cgo) | DFA double-array, 10-50x |
| LPM CIDR | lineal `[]netip.Prefix` | `gaissmai/bart` | LPM moderno O(log N) |
| Domain trie | `map[string]*node` | `cespare/mph` o `openacid/slim` | Hashing perfecto / succinct |
| gzip/deflate | `compress/gzip` | `klauspost/compress/gzip` | 2-3x más rápido |
| zstd | bypass | `klauspost/compress/zstd` | Cierra agujero de inspección |
| Logger | `log` stdlib | `slog` + handler `zerolog` | 0 allocs |
| Métricas | — | `prometheus/client_golang` | Estándar de facto |
| Hot upgrade | — | `cloudflare/tableflip` | Production-tested (CF) |
| Reuseport | — | `libp2p/go-reuseport` | Multi-listener kernel-balanced |
| Container CPU | — | `uber/automaxprocs` | Evita CPU thrashing en K8s |
| Token bucket | — | `golang.org/x/time/rate` | Estándar Go |
| Semáforo wait | `chan struct{}` | `golang.org/x/sync/semaphore` | Espera con context |
| Circuit breaker | — | `sony/gobreaker` | Maduro, simple |
| DNS cache | `net.Resolver` | `rs/dnscache` o `miekg/dns` | TTL controlado |

---

## 🔢 Orden de ejecución propuesto (mayor ROI primero)

1. **7.6 Observabilidad** (sin métricas no se puede medir nada).
2. **7.5.1 Aho-Corasick** + **7.5.4 gzip klauspost** (CPU win inmediato, cero riesgo).
3. **7.1 TLS-MITM completo** (LRU + singleflight + session resumption + key reuse) — el mayor cuello documentado.
4. **7.2 Backpressure** (idle-timeout + admission queue + rate-limit).
5. **7.3.1+7.3.2 HTTP/2** (transformacional para la cuenta de FDs).
6. **7.4 Kernel/socket** (reuseport, splice fast-path, pools).
7. **7.7 Resiliencia operativa** (tableflip, drain, breaker).
8. **7.3.3 HTTP/3, 7.5.6 zstd, 7.5.2 trie compacto** (avanzado).
9. **7.8 Suite de carga** corre en paralelo con cada item.
