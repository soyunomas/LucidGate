# E2Guardian List Compatibility

Referencia practica entre las listas declaradas por e2guardian v5.5 y las listas
o configuraciones equivalentes de LucidGate.

Fuente e2guardian usada como base: `configs/e2guardianf1.conf.in` en
`https://github.com/e2guardian/e2guardian/tree/v5.5`.

Notas:

- "Sin equivalente directo" significa que LucidGate no tiene hoy una lista con
  esa semantica exacta.
- "Parcial" significa que LucidGate cubre el caso principal, pero no toda la
  semantica de e2guardian.
- Las listas LucidGate cargadas por `[rules].include_dir` se reconocen por
  nombre de fichero. Las listas de `substitution`, `masking` y algunas listas
  semanticas tambien pueden cargarse con claves dedicadas en TOML.

| Familia | Lista e2guardian | LucidGate / equivalente | Para que sirve |
| --- | --- | --- | --- |
| MITM cert | `nocheckcertsitelist` | `nocheckcertsitelist` | Totalmente implementado: evita comprobar certificados upstream para dominios concretos (exclusión TLS explícita). |
| MITM cert | `nocheckcertsiteiplist` | `nocheckcertsiteiplist` | Totalmente implementado: evita comprobar certificados upstream para IPs concretas (exclusión TLS explícita). |
| MITM scope | `greysslsitelist` | `greysslsitelist` | Totalmente implementado: define sitios SSL que deben entrar en modo MITM/intercepción para inspección forzada. |
| MITM scope | `greysslsiteiplist` | `greysslsiteiplist` | Totalmente implementado: define IPs SSL que deben entrar en modo MITM/intercepción para inspección forzada. |
| MITM scope | `localgreysslsitelist` | `localgreysslsitelist` | Totalmente implementado: versión local/prioritaria de grey SSL por dominio. |
| MITM scope | `localgreysslsiteiplist` | `localgreysslsiteiplist` | Totalmente implementado: versión local/prioritaria de grey SSL por IP. |
| Site | `bannedsitelist` | `bannedsitelist` | Bloquea dominios antes de abrir upstream. |
| Site | `exceptionsitelist` | `exceptionsitelist` | Permite dominios y gana sobre bloqueos de dominio. |
| Site regex | e2guardian usa regexp site lists en varias categorias | `bannedregexpsitelist`, `exceptionregexpsitelist` | Bloquea o permite dominios por Go/RE2 regex. |
| Site IP | `bannedsiteiplist` | `bannedsiteiplist` | Bloquea por IP/CIDR de destino antes de abrir upstream, tanto si el host ya es IP literal como si requiere una unica resolucion DNS reutilizada para el dial. |
| Site IP | `exceptionsiteiplist` | `exceptionsiteiplist` | Permite IPs/CIDRs de destino concretas y gana sobre `bannedsiteiplist`. |
| Site IP grey | `greysiteiplist` | `greysiteiplist` | Compatibilidad: acepta IP/CIDR y permite el trafico manteniendo inspeccion normal de contenido. |
| URL | `bannedurllist` | `bannedurllist` | Bloquea URL por prefijo cuando la URL ya es conocida. |
| URL | `exceptionurllist` | `exceptionurllist` | Permite URL por prefijo y gana sobre bloqueos de URL. |
| URL regex | `bannedregexpurllist` | `bannedregexpurllist` | Bloquea URL por regex. |
| URL regex | `exceptionregexpurllist` | `exceptionregexpurllist` | Permite URL por regex y gana sobre bloqueos regex. |
| Semi-exception | `semiexceptionsitelist`, `localsemiexceptionsitelist` | `greysitelist` / `localgreysitelist` (alias) | Totalmente implementado como alias funcional de grey lists: permite fetch manteniendo inspección de contenido. Las variantes IP (`semiexceptionsiteiplist`, `localsemiexceptionsiteiplist`) se cargan en `greysiteiplist`. |
| Grey URL/site | `greysitelist`, `greyurllist`, `localgreysitelist`, `localgreyurllist` | `greysitelist`, `greyurllist`, `localgreysitelist`, `localgreyurllist` | Totalmente implementado: permite fetch pero mantiene inspeccion normal de contenido con precedencia e2guardian. |
| Local URL/site | `localexceptionsitelist`, `localexceptionurllist`, `localbannedsitelist`, `localbannedurllist` | `localexceptionsitelist`, `localexceptionurllist`, `localbannedsitelist`, `localbannedurllist` | Totalmente implementado con precedencia estricta: local exception > local grey > local banned > main exception > main grey > main banned. |
| SSL banned | `bannedsslsitelist`, `localbannedsslsitelist` | Parcial: `bannedsitelist`/`bannedurllist` | Bloqueo especifico de SSL en e2guardian. En LucidGate el bloqueo no distingue por familia SSL dedicada. |
| File extension | `bannedextensionlist` | `bannedextensionlist` | Bloquea descargas por extension en URL o nombre de fichero. |
| File extension | `exceptionextensionlist` | `exceptionextensionlist` | Permite extensiones que normalmente estarian bloqueadas. |
| MIME | `bannedmimetypelist` | `bannedmimetypelist` | Bloquea respuestas por `Content-Type` antes de entregar el body. |
| MIME | `exceptionmimetypelist` | `exceptionmimetypelist` | Permite MIME types bloqueados. |
| Filename | e2guardian cubre excepciones por site/url de fichero | `bannedfilenamelist`, `exceptionfilenamelist` | Bloquea o permite por basename de URL o `Content-Disposition`. |
| Download manager | listas `trickle*`, `fancy*` | Parcial: `downloadmanager` | En e2guardian activa gestores de descarga; en LucidGate resume reglas declarativas `banned/exception ext-or-mime valor`. |
| Blanket/time | `blankettimelist`, `bannedtimelist` | `blankettimelist`, `bannedtimelist` + `[schedule.window]` | Implementado: carga timelists e2guardian con formato `start_hour start_min end_hour end_min days` y las compila a ventanas de schedule por perfil. `bannedtimelist` bloquea acceso durante la franja; `blankettimelist` se mapea al mismo bloqueo temporal porque LucidGate no expone storyboard separado de "solo excepciones". |
| TLD blanket | `allowedtldlist`, `blanketblocktldlist` | `allowedtldlist`, `blanketblocktldlist` | Totalmente implementado: permite bloquear o autorizar TLDs enteros con complejidad O(1) in-place. |
| User-Agent | `bannedregexpuseragentlist` | Parcial: `bannedheaderlist` | Bloquea `User-Agent` usando una regla sobre headers. LucidGate usa substring, no regex especifica. |
| User-Agent | `exceptionregexpuseragentlist` | Parcial: `exceptionheaderlist` | Permite `User-Agent` con excepcion de header. LucidGate usa substring. |
| Referer | `refererexceptionsitelist`, `refererexceptionsiteiplist`, `refererexceptionurllist` | `refererexceptionsitelist`, `refererexceptionsiteiplist`, `refererexceptionurllist` | Implementado: parsea el header `Referer`, compara host por trie de dominios, host IP por tabla BART y URL por prefijo. Solo activa bypass de filtros de contenido; no overridea bloqueos previos de destino. |
| Referer embedded | `embededreferersitelist`, `embededrefererurllist` | Sin equivalente directo | Extrae URLs referidas embebidas y las reevalua contra listas de referer. |
| URL rewrite | `urlregexplist` | `urlregexplist` | Totalmente implementado: reescribe URL al vuelo (ruta, query-params) conservando host mediante guardrail. |
| SSL target rewrite | `sslsiteregexplist` | Sin equivalente directo | Cambia el destino upstream de una conexion SSL sin cambiar la URL original. |
| Redirect | `urlredirectregexplist` | `urlredirectregexplist` | Totalmente implementado: redirige mediante HTTP 302 con fast-fail sin conectar upstream. |
| Log URL/site | `logsitelist`, `logsiteiplist`, `logurllist`, `logregexpurllist` | `logsitelist`, `logsiteiplist`, `logurllist`, `logregexpurllist`, `logregexpsitelist` | Marca trafico para auditoria sin bloquear. `logsiteiplist` aplica a hosts que ya son IP literales; la evaluacion por IP destino resuelta queda para fases posteriores. |
| Log exceptions | listas `exceptionlog*` / nolog en e2guardian | `exceptionlogurllist`, `exceptionlogregexpurllist`, `exceptionlogregexpsitelist`, `exceptionlogphraselist` | Suprime auditoria selectiva cuando una excepcion coincide. |
| No-log | `nologsitelist`, `nologsiteiplist`, `nologurllist`, `nologregexpurllist`, `nologextensionlist` | `nologsitelist`, `nologsiteiplist`, `nologurllist`, `nologregexpurllist`, `nologextensionlist` | Reduce ruido en logs/auditoria. `nologsiteiplist` aplica a hosts que ya son IP literales. |
| Alert log | `alertcategorylist` | `alertcategorylist` | Totalmente implementado: duplica logs de categorias coincidentes a un log de alertas separado asíncronamente sin bloqueos. |
| Phrase hard block | `bannedphraselist` | `bannedphraselist` | Bloquea por frases en cuerpos textuales de request/response inspeccionables. |
| Phrase weighted | `weightedphraselist` | `weightedphraselist` | Suma puntuacion por frases y bloquea al superar el umbral. |
| Phrase exception | `exceptionphraselist` | `exceptionphraselist` | Suprime bloqueos semanticos posteriores dentro del mismo stream. |
| Weighted exception | `weightedphraseexceptions` | `weightedphraseexceptions` | Excluye frases del scoring ponderado en LucidGate. |
| Old phrase lists | `oldbannedphraselist`, `oldweightedphraselist`, `oldexceptionphraselist` | `oldbannedphraselist`, `oldweightedphraselist`, `oldexceptionphraselist` | Totalmente implementado: reconocido como alias directo de las listas de frases modernas correspondientes. |
| Search terms | `searchregexplist` | Sin equivalente directo | Extrae terminos de busqueda desde URLs de buscadores. |
| Search exceptions | `searchexceptionregexplist` | Sin equivalente directo | Evita detectar ciertas URLs como busquedas. |
| Search block | `bannedsearchlist`, `bannedsearchoveridelist`, `localbannedsearchlist` | Parcial: `bannedurllist`/`bannedregexpurllist` o frases | Bloquea combinaciones de terminos de busqueda. LucidGate no extrae terminos como familia propia. |
| Search phrase mode | `bannedsearchtermlist`, `weightedsearchtermlist`, `exceptionsearchtermlist` | Sin equivalente directo | Aplica listas semanticas especificas a terminos de busqueda extraidos. |
| Antivirus exception | `exceptionvirusmimetypelist`, `exceptionvirusextensionlist`, `exceptionvirussitelist`, `exceptionvirusurllist` | Sin equivalente directo | Evita escaneo antivirus para MIME/ext/site/url concretos. |
| Request header rewrite | `headerregexplist` | `headerregexplist` | Totalmente implementado: reescribe o elimina headers HTTP de request con formato `pattern => replace` y salvaguarda de framing. |
| Request header add | `addheaderregexplist` | `addheaderregexplist` | Totalmente implementado: añade headers HTTP incondicionalmente o condicionalmente basados en regex del URL. |
| Request header block | `bannedregexpheaderlist` | `bannedregexpheaderlist` | Bloquea requests/responses por regex contra `Header-Name: value`. |
| Request header exception | `exceptionregexpheaderlist` | `exceptionregexpheaderlist` | Excepcion regex para bloqueo por header. |
| Response header rewrite | `responseheaderregexplist` | `responseheaderregexplist` | Totalmente implementado: reescribe o elimina headers HTTP de respuesta antes de enviarlas al cliente o evaluarlas. |
| Cookie block | e2guardian via header regex/rewrite | `bannedcookiephraselist` | Bloquea frases en `Cookie` y `Set-Cookie`. |
| Cookie exception | e2guardian via header exception/rewrite | `exceptioncookiephraselist` | Permite cookies que coinciden con reglas de bloqueo. |
| Client IP block | e2guardian lo suele resolver con auth/story/filter group | `bannedclientiplist` | Bloquea clientes por IP o CIDR antes de procesar la request. |
| Client IP exception | e2guardian lo suele resolver con auth/story/filter group | `exceptionclientiplist` | Permite clientes que coinciden con un bloqueo por IP/CIDR. |
| Groups | `filtergroupslist` | `filtergroupslist` | Define perfiles/grupos ordenados para aplicar politicas por cliente. |
| IP groups | `e2guardianipgroups` | `e2guardianipgroups` | Mapea IP/CIDR de cliente a un grupo/perfil. |
| Bypass denied page | `domainsnobypass`, `ipnobypass`, `urlnobypass` | Sin equivalente directo | Impide usar el bypass temporal en ciertos destinos. |
| Response substitution | No es una lista clasica de e2guardian en `e2guardianf1.conf.in` | `substitutionlist`, `regexsubstitutionlist` | Reescribe cuerpos textuales de respuesta que LucidGate recibe del upstream antes de entregarlos al cliente. |
| Response masking | No es una lista clasica de e2guardian en `e2guardianf1.conf.in` | `maskedphraselist` | Enmascara frases en respuestas textuales no HTML conservando longitud. |
| Request body rewrite | POST protection aparece como no implementado en e2guardian v5 | `requestsubstitutionlist`, `requestregexsubstitutionlist` | Extensión propia de LucidGate: muta cuerpos POST/PUT/PATCH en streaming mediante sustituciones literales y expresiones regulares (con captures). |
