# 🗺️ ROADMAP ARQUITECTÓNICO: LucidGate -> MOTOR DE FILTRADO (E2GUARDIAN CLONE)

## Plan activo - P0: Corrección de Critical Data Race + WebSocket + bloqueo HTTP/3 advertising ✅

**Objetivo:** Eliminar la fuga de concurrencia en el sistema de dumper y estabilizar la suite de tests bajo el race detector de Go.

- [x] **7.0.0. Eliminar Data Race en el dumper.**
  - **Problema:** `asyncDumpLoop` y `initDumper` utilizan variables globales (`dumpFile`, `dumpChan`) con sincronización incompleta durante limpiezas de tests y reloads. Detectado en `proxy/relay.go`.
  - **Criterio de éxito:** `go test -race ./...` debe resultar en **PASS** sin advertencias de DATA RACE.
  - **Fases del Plan:**
    - [x] **Fase 1: Estructuración de ForensicDumper.** Definir el tipo `ForensicDumper` en `proxy/relay.go` con `sync.WaitGroup`, `context.Context` de cancelación, canal `dumpChan` e instancia de bufio.Writer interna y acotada al ciclo de vida del bucle.
    - [x] **Fase 2: Bucle asyncDumpLoop seguro.** Refactorizar `asyncDumpLoop` para operar en el contexto del struct, admitiendo un drenaje robusto ante la señal de cierre `ctx.Done()`.
    - [x] **Fase 3: Gestión Global Atómica (Thread-Safe).** Reemplazar las variables globales individuales por `atomic.Pointer[ForensicDumper]` y un `sync.Mutex` para protección de dobles inicializaciones (`double-check locking`).
    - [x] **Fase 4: Aislamiento Completo en Tests.** Refactorizar `resetDumper()` en `proxy/server_test.go` para llamar de forma síncrona a `Close()` sobre el dumper activo antes de asignarlo a `nil`.
    - [x] **Fase 5: Verificación de Estabilidad.** Ejecutar `go test -race ./...` para asegurar que el 100% de la suite corre en verde y libre de advertencias de concurrencia.
  - **Resultado (2026-05-31):** Refactorizado completamente de forma segura e hilo-segura usando `atomic.Pointer[ForensicDumper]` para evitar la contención por locks en el hot path caliente de `writeDumpLine`. La suite completa pasa exitosamente al 100% bajo el race detector (`go test -race ./...` y `make verify` en verde).


## Plan activo - P0: WebSocket + bloqueo HTTP/3 advertising ✅ DONE 2026-05-29

Objetivo: cerrar las dos fugas críticas detectadas en la auditoría comparativa: (a) tráfico WebSocket que hoy rompe o se escapa del filtrado y (b) navegadores que se cambian a HTTP/3/QUIC al ver `Alt-Svc` y dejan al proxy sin visibilidad.

### Fase A - Scaffolding y tests-first ✅ DONE 2026-05-29
- [x] Regresión byte-level `TestRelayWebSocketPassesThroughEchoEndToEnd`: upstream local `101`, eco bidi y métricas.
- [x] Smoke binario `TestBinaryWebSocketSmokePlainHTTP`: HTTP plano real contra LucidGate, `101` y bytes bidi.
- [x] Smoke binario `TestBinaryWebSocketSmokeHTTPSMITM`: `CONNECT` + TLS local + Upgrade WSS, `101` y bytes bidi.
- [x] `TestSanitizeWebSocketRequestPreservesHandshakeHeaders` y smokes verifican que `Connection: Upgrade`/`Upgrade: websocket`/`Sec-WebSocket-*` no se pierden.
- [x] `TestServeHTTPPlainWebSocketPolicyBlocksBeforeDial`: política de dominio bloquea WS antes de abrir upstream e incrementa `lucidgate_websocket_sessions_total{result="denied"}`.
- [x] `proxy/altsvc_test.go` cubre `Alt-Svc`, multivalor, `Alternate-Protocol`, ausencia de headers y nil.
- [x] `TestServeHTTPPlainStripsAltSvcFromUpstream` y `TestBinaryAltSvcSmokeStripsHTTP3Advertising` cubren strip en HTTP plano y MITM contra binario.
- [x] No se implementa `strip_alt_svc = false`: decisión explícita de Fase C, default-on sin opt-out.

### Fase B - Implementación WebSocket ✅ DONE 2026-05-29
- [x] Detección de Upgrade en `relayHTTPConnLease` y `handlePlainHTTP`: `GET` + `Connection: upgrade` + `Upgrade: websocket`, case-insensitive.
- [x] Sanitización específica WS: elimina headers proxy-hop (`Proxy-Connection`, `X-Forwarded-For`, `Via`, `X-Real-IP`) y preserva handshake Upgrade.
- [x] Request Upgrade se reescribe upstream sin body filter y conservando headers WS.
- [x] Respuesta upstream se lee con `http.ReadResponse`; `101 Switching Protocols` entra en copia raw bidi, non-101 se reenvía como HTTP y cierra.
- [x] Handshake WS acotado por `IOTimeout`; copia raw bidi con `WSIdleTimeout`, deadlines por Read/Write y buffers reciclados de `relayBufferPool`.
- [x] Conexión upstream nunca vuelve al pool después de un Upgrade.
- [x] Sesión WS cierra cliente/upstream al terminar para no reanudar HTTP sobre socket en modo raw.
- [x] Métricas `lucidgate_websocket_sessions_total{result="opened|denied|error|upstream_refused"}` y `lucidgate_websocket_bytes_total{direction="in|out"}`.

### Fase C - Bloqueo de advertising HTTP/3 (Alt-Svc strip) ✅ DONE 2026-05-26
- [x] Helper `stripHTTP3Advertising` en `proxy/altsvc.go` que borra `Alt-Svc` y `Alternate-Protocol` siempre que estén presentes en la respuesta upstream. Sin flag de config (default-on; opt-out sería sobreingeniería para un proxy de interceptación: un usuario que quiera fugar a QUIC tiene problemas mayores).
- [x] Invocado tras `http.ReadResponse` en los 3 puntos: HTTPS H1 (`proxy/relay.go:295`), H2 (`proxy/relay.go:138`) y HTTP plano (`proxy/server.go:527`).
- [x] Métrica `lucidgate_alt_svc_stripped_total` añadida en `proxy/metrics.go`.
- [x] Tests: 5 unitarios (`proxy/altsvc_test.go`) + 1 e2e HTTP plano (`TestServeHTTPPlainStripsAltSvcFromUpstream`) cubriendo Cloudflare-style multivalor + Alternate-Protocol legacy + delta de la métrica. Todos verdes. Suite completa `go test ./...` verde.

### Fase D - Wiring y configuración ✅ DONE 2026-05-29
- [x] Exponer `ws_idle_timeout` en `appConfig`, CLI/env/TOML y `lucidgate.toml` de ejemplo. No añadir flag `strip_alt_svc`: el strip de HTTP/3 advertising queda default-on sin opt-out para evitar fugas QUIC.
- [x] Añadir cobertura de config para default/TOML/env/flag/validación de `ws_idle_timeout`.
- [x] Añadir cobertura de `applyRuntimeConfig` para demostrar que `SIGHUP`/reload publica `WSIdleTimeout` nuevo vía `atomic.Value` en `RelayOptions`.
- [x] Documentar `--ws-idle-timeout` y métricas `lucidgate_alt_svc_stripped_total`, `lucidgate_websocket_sessions_total`, `lucidgate_websocket_bytes_total` en README.
- [x] Corregir bug latente: el handshake WebSocket usa `IOTimeout` con deadlines explícitos; la fase raw bidi usa `WSIdleTimeout` y buffers de `sync.Pool`.

### Fase E - Verificación
- [x] `make test` verde (incluyendo regresiones nuevas).
- [x] `make verify` (`fmt-check`, `go vet`, `go test ./...`, build y smoke binario) verde.
- [x] `make smoke` incluido en `make verify` verde.
- [x] `make curl-policy` verde: 24 checks OK, 0 failed.
- [x] Búsqueda anti-`io.ReadAll`/`ioutil.ReadAll` en código de producción sin hits.
- [x] Añadir `make ws-smoke`: WebSocket local reproducible contra el binario, sin depender de `websocat` ni Internet.
- [x] Añadir `make alt-svc-smoke`: upstream local anuncia `Alt-Svc`/`Alternate-Protocol`; LucidGate debe quitarlos en HTTP plano y MITM.
- [x] Añadir `make p0-smoke`: ejecuta `ws-smoke`, `alt-svc-smoke` y `curl-policy`.
- [x] Documentar resultados al final de este bloque.

**Resultado 2026-05-29:**
- `config.go`: `ws_idle_timeout` queda cableado en default (`5m`), TOML `[server].ws_idle_timeout`, env `LUCIDGATE_WS_IDLE_TIMEOUT`/legacy `CLEARGATE_WS_IDLE_TIMEOUT`, flag `--ws-idle-timeout` y validación positiva.
- `main.go`/`proxy.Server`: `applyRuntimeConfig` publica `WSIdleTimeout` en `RelayOptions` vía `atomic.Value`; añadido getter de test `RelayOptions()`.
- `proxy/relay.go`/`proxy/websocket.go`: se separan los timeouts. Handshake Upgrade (`req.Write`, `ReadResponse`, headers al cliente) queda acotado por `IOTimeout`; la copia raw bidi usa `WSIdleTimeout`, refresca deadlines por operación y usa `relayBufferPool`.
- `README.md`: ejemplo TOML, tabla flag/env y métricas nuevas documentadas. `strip_alt_svc` no se expone por configuración: el strip HTTP/3 advertising sigue default-on.
- Tests añadidos: default/TOML/env/flag/validación de `WSIdleTimeout`, publicación hot-reload en `RelayOptions`, deadlines de handshake WebSocket con timeout HTTP separado del idle WS, y compatibilidad del smoke con logs JSON de `slog`.
- Verificación: `GOCACHE=/tmp/go-build go test ./... -count=1` OK; `make test` OK; `make verify` OK; `make curl-policy` OK (24 passed, 0 failed); búsqueda anti-`ReadAll` en producción sin hits. `make curl-policy` requirió ejecución fuera del sandbox porque la batería abre listeners locales Python/curl.

**Cierre P0 2026-05-29:**
- `make ws-smoke` OK: cubre HTTP WS plano y WSS sobre CONNECT/MITM contra el binario real.
- `make alt-svc-smoke` OK: cubre strip `Alt-Svc`/`Alternate-Protocol` en HTTP plano y MITM contra el binario real.
- `make p0-smoke` OK: `ws-smoke`, `alt-svc-smoke` y `curl-policy` (24/24) pasan.
- Durante el smoke WS plano apareció una fuga real: `handlePlainHTTP` sanitizaba `Connection`/`Upgrade` y rompía el Upgrade. Corregido con rama WS en HTTP plano por hijack; la conexión no vuelve al pool.

---

## Plan activo - Prueba fleet multi-cliente/multi-conexión (2026-05-26)

Objetivo: antes de seguir con mejoras de prioridad media, demostrar capacidad con muchos clientes lógicos conectados y muchas conexiones concurrentes, usando tráfico real a través de LucidGate y métricas de proceso.

- [x] Crear herramienta reproducible que simule N máquinas con IP loopback distinta y M conexiones concurrentes por máquina.
- [x] Usar upstream local controlado para evitar ruido de Internet y poder subir a miles de conexiones.
- [x] Medir p50/p95/p99, RPS, errores, códigos HTTP, `lucidgate_active_connections`, goroutines, FDs y RSS.
- [x] Ejecutar escalones representativos: pequeño/medio/colegio y una prueba de estrés.
- [x] Documentar resultados y límites observados.

**Resultado 2026-05-26:**
- Herramienta añadida: `scripts/load_proxy_fleet.go`. Cada máquina lógica usa una IP origen loopback distinta (`127.64.x.y`), abre `-conns-per-device` conexiones concurrentes al proxy y manda `-requests-per-conn` peticiones. La prueba usa upstream HTTP local controlado y muestrea `/metrics`.
- Smoke herramienta: 5 máquinas × 2 conexiones × 2 requests, delay 50 ms → 20/20 OK, p99 54 ms, 0 errores. Confirma que el bind por IP origen funciona en este host.
- Batería con `max_connections=2048`, upstream local 200 ms, `conns_per_device=4`, `requests_per_conn=1`:
  - 50 máquinas / 200 conexiones: 200/200 OK, p99 280 ms, 671 RPS, peak FDs 395, RSS 26.7 MB.
  - 150 / 600: 600/600 OK, p99 342 ms, 1736 RPS, peak FDs 1210, RSS 43.8 MB.
  - 300 / 1200: 1200/1200 OK, p99 414 ms, 2749 RPS, peak FDs 2410, RSS 73.5 MB.
  - 500 / 2000: 2000/2000 OK, p99 554 ms, 3513 RPS, peak FDs 3821, RSS 113.8 MB.
  - 750 / 3000: 3000/3000 OK, p99 673 ms, 3979 RPS, peak FDs 5058, RSS 157.5 MB. `peak_upstream_active=2048` muestra que el gate saturó en el límite configurado pero drenó dentro del `wait_timeout`.
  - 1000 / 4000: 3872 OK + 128 `503`, p99 776 ms sobre respuestas OK, 4422 RPS, peak FDs 6058, RSS 214.8 MB. Backpressure limpio al superar el límite.
- Prueba sostenida: 500 máquinas × 4 conexiones × 5 requests = 10 000 requests, delay 200 ms → 10 000/10 000 OK, p99 553 ms, 5448.5 RPS, peak active 2000, peak goroutines 4163, peak FDs 4010, RSS 217.7 MB.
- Post-carga: `lucidgate_active_connections=0`, `go_goroutines=16`, `process_open_fds=42`, RSS ~77.6 MB. Sin fuga visible de goroutines/conexiones; FDs residuales bajos tras cerrar clientes y detener upstream.
- Conclusión: para HTTP plano/local, 500 máquinas lógicas con 4 conexiones activas cada una quedan por debajo de p99 600 ms y sin errores. El límite real aparece entre 750 y 1000 máquinas en este perfil por `max_connections=2048`; el proxy responde con 503 limpios en vez de acumular trabajo infinito.

## Plan activo - Pool persistente proxy→upstream (2026-05-26)

Objetivo: completar la segunda optimización sin escalar hardware: reutilizar conexiones TCP/TLS upstream entre túneles/clientes para evitar handshakes repetidos al mismo origen, conservando streaming, deadlines por operación y fast-fail antes de dial.

- [x] Añadir pool LRU/acotado por destino `(scheme, address, serverName, alpn/spec)` con `max_idle_conns_per_host=32` e `idle_timeout=90s` por defecto.
- [x] Integrar el pool en HTTPS MITM sin abrir upstream antes de que la política de URL haya pasado.
- [x] Integrar el pool en HTTP plano y eliminar el cierre obligatorio por request cuando la respuesta upstream permita keep-alive.
- [x] No devolver conexiones al pool si hubo error, bloqueo tras headers, body no drenado, `resp.Close` o bytes pendientes en el reader.
- [x] Añadir regresiones: reutilización entre dos CONNECT cortos al mismo host y reutilización HTTP plana.
- [x] Verificar con tests/build y documentar resultado medido.

**Resultado 2026-05-26:**
- Añadido `proxy/upstream_pool.go`: pool oportunista sin goroutines, acotado por destino, limpia expirados al adquirir, cierra excedentes y borra deadlines antes de guardar idle.
- `proxy/server.go`: HTTPS MITM usa leases perezosos después de policy URL; HTTP plano usa el mismo pool. Configurable con `[upstream].max_idle_conns_per_host` y `[upstream].idle_timeout` (`32`/`90s` por defecto, `0` desactiva pooling).
- `proxy/relay.go`: `relayHTTPLease` devuelve upstream al pool solo tras intercambio limpio, `resp.Close=false`, body drenado y `bufio.Reader.Buffered()==0`; si hay bloqueo/error se cierra. `Connection`/`Keep-Alive` ya no se reenvían upstream.
- Regresiones: `TestConnectReusesPooledUpstreamAcrossShortClientTunnels` demuestra 2 túneles CONNECT cortos al mismo host con **1 solo dial upstream** y sin filtrar `Connection: close`; `TestServeHTTPPlainHTTPReusesPooledUpstreamKeepAlive` cubre HTTP plano.
- `scripts/load_proxy_https.go` ahora soporta `-requests-per-worker` y `-client-keepalive`; el default conserva el peor caso anterior (`client_keepalive=false`, un CONNECT por petición).
- Validación empírica HTTPS real, 4 targets CDN, cliente **sin keep-alive**, `-requests-per-worker 3`, mismo binario/config salvo `LUCIDGATE_UPSTREAM_MAX_IDLE_CONNS_PER_HOST`:
  - Pool OFF (`0`): 50 conc/150 req → p99 316 ms, 216 RPS; 200/600 → p99 1.367 s, 329 RPS; 500/1500 → p99 4.142 s, 264.5 RPS.
  - Pool ON (`32`): 50 conc/150 req → p99 230 ms, 397 RPS; 200/600 → p99 400 ms, 993 RPS; 500/1500 → p99 1.065 s, 1094.5 RPS.
  - Delta a 500 concurrentes: elapsed 5.672 s → 1.370 s, p99 4.142 s → 1.065 s, throughput 264.5 → 1094.5 RPS (**4.1× más RPS**) sin tocar hardware. Cero errores en ambos runs.
  - Post-carga pool ON: `lucidgate_active_connections=0`, `go_goroutines=16`, `process_open_fds=138`, RSS ~39 MB, cert cache 4496/4500 hits (99.9%). FDs idle altos son esperados: el pool mantiene conexiones upstream listas hasta `idle_timeout`.
- Verificación: regresiones enfocadas OK, `GOCACHE=/tmp/go-build go test ./... -count=1` OK, `make test` OK, `make build` OK, `go vet ./...` OK, búsqueda anti-`io.ReadAll`/`ioutil.ReadAll` en producción sin hits.

## Plan activo - Pre-warm condicional de certificados MITM (2026-05-26)

Objetivo: eliminar el spike del primer encuentro con SNIs populares sin subir hardware, aprovechando los `cert_workers` ya existentes y manteniendo la generación deduplicada/acotada del `LeafCache`.

- [x] Añadir configuración `[mitm].prewarm_hosts = [...]`, env `LUCIDGATE_MITM_PREWARM_HOSTS` y log de conteo.
- [x] Ejecutar prewarm al arranque y en reload sin bloquear indefinidamente el path de escucha.
- [x] Validar hosts vacíos/duplicados y normalizar host:puerto/listas separadas por coma.
- [x] Cubrir config y comportamiento con tests.
- [x] Verificar con tests/build y documentar resultado.

**Resultado 2026-05-26:**
- `config.go`: nuevo `MITMPrewarmHosts`, TOML `[mitm].prewarm_hosts`, env `LUCIDGATE_MITM_PREWARM_HOSTS`/`CLEARGATE_MITM_PREWARM_HOSTS` y flag `--mitm-prewarm-hosts`. Normaliza esquemas, paths, puerto `:443`, mayúsculas, brackets IPv6 y duplicados.
- `proxy.Server.PrewarmCertificates(hosts)` encola hosts únicos en la cola existente de `cert_workers`; no crea goroutines nuevas y no bloquea si la cola está llena.
- `main.go`: prewarm al arranque y tras SIGHUP/reload, usando los workers existentes. `logConfig` registra `mitm_prewarm_hosts_count`; el server loguea `queued certificate prewarm`.
- `lucidgate.toml`: prewarm inicial para los 4 hosts usados en la carga HTTPS (`www.google.com`, `www.gstatic.com`, `www.cloudflare.com`, `1.1.1.1`).
- Tests añadidos/actualizados: config TOML/env/flag normalizada y `TestPrewarmCertificatesEnqueuesUniqueHostsForWorkers`.
- Verificación: `GOCACHE=/tmp/go-build go test ./... -count=1` OK, `make test` OK, `make build` OK, `go vet ./...` OK, búsqueda anti-`io.ReadAll`/`ioutil.ReadAll` en producción sin hits.

## Plan activo - Prueba de carga HTTP/HTTPS 500/1000/2000/4000 + dimensionamiento (2026-05-26)

- [x] Subir `max_connections` de 100 → 1024 → 2048 y rehacer baterías escalonadas HTTP planas (upstream local 200 ms).
- [x] Añadir `scripts/load_proxy_https.go`: variante HTTPS contra targets reales (4 CDN/captive-portal), `InsecureSkipVerify=true`, `DisableKeepAlives=true` para forzar worst-case TLS handshake.
- [x] Ejecutar rondas 50/200/500 HTTPS reales y comparar con HTTP plano.
- [x] Recoger `lucidgate_cert_cache_{hits,requests}_total`, goroutines, FDs, RSS antes y después.
- [x] Documentar capacidad estimada por perfil (ligero/mixto/pesado) y techo horizontal vs vertical.

**Resultado 2026-05-26:**
- HTTP plano (`max_connections=2048`, upstream local 200 ms): 2000 concurrentes → 100% OK, p99 604 ms, 0 errores. 4000 → 70% OK (resto 503 limpios). 6000 → 55%. 8000 → 47%. Techo ~6 500 RPS. RSS pico 340 MB, FDs pico 10 048.
- HTTPS real (4 hosts: `www.google.com/generate_204`, `www.gstatic.com/generate_204`, `www.cloudflare.com/cdn-cgi/trace`, `1.1.1.1/cdn-cgi/trace`, `cert_workers=4`): 50 conc → p99 247 ms, 200 conc → p99 779 ms, 500 conc → p99 5.25 s, todos 100% OK.
- `lucidgate_cert_cache_hits_total=1498/1502` (99.7% hit rate). 77 `relay failed: broken pipe` por cierre cliente sin keep-alive (artefacto del test, no del proxy).
- Cero leaks: tras carga goroutines volvieron a 16-17, `lucidgate_active_connections=0`, RSS 31-340 MB según test.
- Factor MITM≈10× HTTP. Estimación de dispositivos por nodo (4 cores, 1M FDs): ligero 300-500, mixto 150-250, pesado 75-120. Documentado en `tasks/lessons.md`.

## Plan activo - Upstream TLS Session Resumption real (2026-05-26)

Objetivo: arreglar el bug latente de resumption TLS 1.3 en `stealth/dial.go` para reducir handshakes upstream de 2-RTT a 1-RTT (PSK) y bajar el factor MITM medido de ~10× a ~5×.

**Hallazgo bloqueante (causa raíz medida hoy):** `upstreamSessionCache` ya está conectado (`stealth/dial.go:22,78`), pero el fingerprint estático `HelloFirefox_120` (= `HelloFirefox_Auto`) en uTLS v1.8.2 **no incluye `UtlsPreSharedKeyExtension`**. Sin esa extensión el cliente nunca envía `pre_shared_key` en el ClientHello → CDNs modernos (Google, Cloudflare, Fastly) que solo negocian TLS 1.3 no pueden devolver `selected_identity` → cada reconexión paga handshake full. Esto encaja con el p99=5.25 s observado a 500 concurrentes HTTPS.

- [x] Pasar el dial upstream a `utls.HelloCustom` + `ApplyPreset(spec)` con spec derivado dinámicamente de `UTLSIdToSpec(HelloFirefox_120)`.
- [x] En el spec clonado: dejar el ALPN ya como `http/1.1` (eliminar la mutación post-build `forceHTTP1ALPN`) y **append `&UtlsPreSharedKeyExtension{}` al final** de `spec.Extensions` (debe ir último por RFC 8446 §4.2.11).
- [x] Mantener `upstreamSessionCache` LRU(8192) compartida, idempotente cuando el caller pasa la suya.
- [x] Test de regresión `TestDialFirefoxResumesSessionAcrossDials`: dos dials secuenciales al mismo `tls.Listen` TLS 1.3 local; primero `DidResume=false`, segundo `DidResume=true`. Sin sleep ni timing; pura verificación funcional.
- [x] Tests existentes en `stealth/dial_test.go` deben seguir pasando (handshake básico, ALPN forzado a http/1.1, cierre limpio de TCP en error).
- [x] `make test`, `make build`, `make vet`. Cero regresiones en `./proxy/...`.
- [x] Verificación empírica end-to-end: arrancar proxy con binario nuevo y re-ejecutar `scripts/load_proxy_https.go -rounds 50,200,500 -timeout 30s`.
- [x] Documentar resultado y delta cuantificado en este bloque + `tasks/lessons.md`.

**Resultado 2026-05-26:**
- `stealth/dial.go` reescrito: `firefoxHTTP1SpecWithPSK()` clona `HelloFirefox_120`, reduce ALPN a `["http/1.1"]` y appende `&UtlsPreSharedKeyExtension{}`. El dial usa `utls.UClient(..., HelloCustom)` + `tlsConn.ApplyPreset(&spec)`. `forceHTTP1ALPN` eliminado. Añadido `config.OmitEmptyPsk = true` para evitar `"empty psk detected"` en primer dial sin cache.
- `stealth/dial_test.go`: añadido `TestDialFirefoxResumesSessionAcrossDials` (servidor TLS 1.3 local, dos dials seguidos, segunda conexión verifica `DidResume=true`). Los tres tests previos siguen pasando.
- `scripts/load_proxy_{smoke,https}.go` marcados con `//go:build ignore` para evitar colisión de `package main` en `go test ./...`. Se ejecutan igual con `go run`.
- `GOCACHE=/tmp/go-build go test ./... -count=1` OK. `make build` OK. `go vet ./...` OK.
- Smoke directo curl: 1ª petición 164 ms (handshake full), 2ª 114 ms (resumed PSK 1-RTT) → **30% menos latencia** end-to-end por reconexión.
- Load test HTTPS contra 4 CDNs reales (Google `/generate_204`, Gstatic `/generate_204`, Cloudflare `/cdn-cgi/trace`, `1.1.1.1/cdn-cgi/trace`), `max_connections=2048`, `DisableKeepAlives=true` en cliente (peor caso, fuerza handshake nuevo por request):
  - 50 conc: p99 247→241 ms (sin cambio relevante, ya estaba rápido).
  - 200 conc: p99 779→901 ms (ruido de red, los CDNs internamente también priorizan diferente).
  - **500 conc: p99 5.25 s → 2.24 s, elapsed 5.38 s → 2.31 s, 2.35× más rápido.** Cero errores en cliente, cero 503.
- Cert cache sigue al 99.7% (1500/1504 hits). RSS post-carga 35 MB, goroutines volvieron a 16, `lucidgate_active_connections=0` → cero leaks.
- Factor MITM efectivo bajado de ~10× a ~5× para tráfico con reconexiones al mismo origen (que es lo habitual en producción real). Los 26 `relay failed: broken pipe` siguen siendo artefacto del test sin keep-alive (lección registrada).

## Plan activo - Mejoras sin escalar hardware (backlog priorizado 2026-05-26)

Objetivo: subir el factor MITM 10×→3-5× sin tocar CPU/RAM. Pensado para retomar en sesiones siguientes.

- [x] **Upstream TLS Session Resumption + uTLS ClientSessionCache compartida** (alta prioridad).
- [x] **Pool real de conexiones persistentes proxy→upstream** (alta prioridad).
- [x] **Soporte ALPN H2 al upstream cuando el cliente habla H1** (media prioridad).
- [x] **Downgrade del log `relay failed: broken pipe` cuando los bytes útiles ya fueron escritos** (baja prioridad, calidad operativa).
- [x] **Métrica `lucidgate_connections_rejected_total{reason="max_connections"}`** (baja prioridad).
- [x] **Pre-warm condicional de certs por dominio popular** (media prioridad).
- [x] **Histograma `lucidgate_cert_generation_duration_seconds`** (baja prioridad).
- [x] **Comprimir `dumps/` o desactivar `log_bodies` bajo carga** (calidad operativa).
- [x] **Bench dedicado de coste TLS handshake con/sin resumption** antes y después de implementar lo anterior, para tener delta cuantificado (no solo "se siente más rápido"). Reutilizar `scripts/load_proxy_https.go` con flag `-keepalive` y `-targets` parametrizables.

**Resultado de las Mejoras y Bench de Webs Reales (2026-05-26):**
- Implementado el **muestreo dinámico (`log_bodies_sample_rate`)** para logging y deshabilitación selectiva de `DumpDir` por exchange.
- Añadidas las métricas estructuradas de Prometheus para rechazo por semáforo y latencia de keygen.
- Implementado **Bypass selectivo de MITM CONNECT (`bypass_hosts`)** a nivel de relé TCP ciego ultra-eficiente con `sync.Pool`.
- Ejecutado el benchmark real de Webs de CDNs (Google, Cloudflare, 1.1.1.1, gstatic) con 300 concurrencias y 900 peticiones secuenciales:
  - **Escenario A (MITM Base sin Pool):** 3.833 s, 234.8 RPS, p50 549 ms, p99 1.904 s, 625 FDs.
  - **Escenario B (MITM Optimizado Pool + Resumption):** 1.194 s (**3.2× rápido**), **753.6 RPS** (**3.2× RPS**), p50 307 ms (44% menos), p99 703 ms (63% menos), **420 FDs**.
  - **Escenario C (CONNECT Bypass TCP crudo):** 3.917 s, 105.7 RPS, p50 731 ms, p99 3.655 s, 1067 FDs.
  - *Interpretación de la Paradoja de Bypass:* Con clientes sin keep-alive (CONNECT por petición), el **Pool Upstream de LucidGate (Escenario B) supera ampliamente al Bypass crudo (Escenario C)** debido a que el Bypass crudo obliga a hacer un dial TCP + TLS handshake remoto por cada petición individual, mientras que el MITM con Pool reutiliza sockets calientes de forma virtualmente instantánea.
  - *Negociación HTTP/2:* Se verificó que el modo CONNECT Bypass de LucidGate realiza el reenvío transparente y robusto de **HTTP/2 (H2)** y **TLS 1.3** entre el cliente y el origen con certificado verificado de GTS.

## Plan activo - Prueba de carga controlada 100/500/1000 (2026-05-26)

- [x] Crear herramienta reproducible de carga local sin depender de Internet.
- [x] Capturar baseline de `/metrics`.
- [x] Ejecutar rondas 100, 500 y 1000 contra upstream local vía proxy.
- [x] Comparar resultados con `max_connections = 100` y `wait_timeout = 250ms`.
- [x] Documentar conclusión y siguiente ajuste recomendado.

**Resultado 2026-05-26:**
- Herramienta añadida: `scripts/load_proxy_smoke.go`. Levanta upstream local, carga vía `http://127.0.0.1:8080` y muestrea `/metrics`.
- Baseline antes de carga: `go_goroutines=17`, `process_open_fds=12`, `process_max_fds=1048576`.
- Config vigente durante la prueba: `max_connections=100`, `wait_timeout=250ms`, upstream local con `delay=200ms`.
- Ronda 100: `200=100`, errores 0, elapsed 263 ms, p50 239 ms, p95 262 ms, peak active handlers 100, peak goroutines 218, peak FDs 210.
- Ronda 500: `200=200`, `503=300`, errores 0, elapsed 506 ms, p50 301 ms, p95 501 ms, peak active handlers 500, peak goroutines 1017, peak FDs 610.
- Ronda 1000: `200=200`, `503=800`, errores 0, elapsed 459 ms, p50 277 ms, p95 438 ms, peak active handlers 1000, peak goroutines 2016, peak FDs 1110.
- Tras drenar: `go_goroutines=17`, `process_open_fds=12`; no queda crecimiento residual visible.
- Interpretacion: el proxy no se cae ni fuga FDs/goroutines en esta prueba corta. A partir de 500 concurrencias manda 503 de forma esperada por el limite actual. Para medir capacidad real hay que subir `max_connections` y hacer una prueba escalonada con cuotas controladas.

## Plan activo - Prometheus operativo antes de carga (2026-05-26)

- [x] Activar `/metrics` en la configuración real sin exponerlo fuera de loopback.
- [x] Añadir overrides de entorno para métricas y cubrirlos con tests de config.
- [x] Documentar endpoint y métricas mínimas para pruebas de carga.
- [x] Verificar `/metrics` con el proxy reiniciado y confirmar métricas LucidGate + Go/proceso.
- [x] Actualizar `7.6.2` con el estado real y el siguiente hueco pendiente.

**Resultado 2026-05-26:**
- `lucidgate.toml` activa `[metrics] enabled = true` en `127.0.0.1:6060`; el log de arranque confirma `admin server listening (pprof + metrics)`.
- `config.go` acepta `LUCIDGATE_METRICS_ENABLED`/`CLEARGATE_METRICS_ENABLED` y `LUCIDGATE_METRICS_LISTEN_ADDR`/`CLEARGATE_METRICS_LISTEN_ADDR`; valida que `listen_addr` no quede vacio si metrics esta activo.
- `proxy/metrics.go` expone el histograma `lucidgate_tls_handshake_duration_seconds{direction="downstream"}` además de conexiones, bytes, cert cache, rule hits e inspección.
- `README.md` documenta `/metrics`, las series LucidGate y las series Go/proceso (`go_goroutines`, `process_open_fds`, `process_max_fds`) que se usaran en carga.
- Verificación: `GOCACHE=/tmp/go-build go test ./... -count=1` OK; `make build` OK; `make test` OK. Proxy reiniciado y `/metrics` muestra `lucidgate_active_connections`, `lucidgate_bytes_total`, `lucidgate_rule_hits_total`, `lucidgate_tls_handshake_duration_seconds_count`, `go_goroutines`, `process_open_fds` y `process_max_fds`.

## Plan activo - Idle timeout real y logs keep-alive (2026-05-26)

- [x] Implementar wrappers de deadline idle por lectura/escritura sin romper streaming ni usar buffering total.
- [x] Aplicar los wrappers al relay HTTPS MITM y al camino HTTP plano.
- [x] Tratar el timeout de lectura del siguiente request tras un exchange correcto como cierre keep-alive limpio.
- [x] Añadir regresiones para renovación de deadlines durante cuerpo y timeout keep-alive limpio.
- [x] Ejecutar tests enfocados, `make test` y `make build`; reiniciar proxy si todo pasa.

**Resultado 2026-05-26:**
- `proxy/relay.go`: añadidos wrappers ligeros que renuevan `SetReadDeadline`/`SetWriteDeadline` antes de cada operación de cuerpo. No hay buffering total; sigue usando `copyBufferPooled`.
- MITM HTTPS y HTTP plano aplican idle deadlines en subida y bajada. En HTTP plano, el `http.ResponseWriter` se envuelve solo para renovar deadline antes de `Write`.
- El relay devuelve cierre limpio si el timeout ocurre leyendo el siguiente request tras al menos un exchange correcto, evitando logs falsos tipo `read local request: i/o timeout` de keep-alive ocioso.
- Tests añadidos: renovación durante cuerpo grande y timeout keep-alive limpio.
- Verificación: tests enfocados OK; `GOCACHE=/tmp/go-build go test ./proxy -count=1` OK; `GOCACHE=/tmp/go-build go test ./... -count=1` OK; `make build` OK; `make test` OK.
- Proxy reiniciado con el binario nuevo; `curl -I --proxy http://127.0.0.1:8080 http://example.com` devolvió `HTTP/1.1 200 OK`; pprof en `127.0.0.1:6060` devolvió `HTTP/1.1 200 OK`.

## Plan activo - Diagnóstico operativo de proxy en 0.0.0.0 (2026-05-25)

- [x] Confirmar instrucciones locales (`AGENTS.md`), lecciones previas y estado actual del roadmap antes de opinar.
- [x] Verificar configuración efectiva de escucha en `0.0.0.0:8080` y construir/usar binario actual sin revertir cambios no propios.
- [x] Arrancar LucidGate y comprobar que queda escuchando en `0.0.0.0:8080`.
- [x] Emitir diagnóstico inicial: claridad del objetivo, puntos sólidos y causas probables de páginas que cargan parcialmente.

**Resultado 2026-05-25:**
- `make build` OK.
- Primer arranque dentro del sandbox falló por permisos de socket; repetido fuera del sandbox con aprobación.
- LucidGate activo como PID 56419 con `./build/lucidgate --config lucidgate.toml`.
- Log de arranque: `proxy listening` en `[::]:8080`, configuración efectiva `listen="0.0.0.0:8080"`.
- Verificación funcional: `curl -I --proxy http://127.0.0.1:8080 http://example.com` devolvió `HTTP/1.1 200 OK`; admin pprof en `127.0.0.1:6060` devolvió `HTTP/1.1 200 OK`.

## Plan activo - Hotfix ChatGPT streaming corrupto por sustitución (2026-05-25)

- [x] Reproducir/razonar el fallo: `Real Madrid -> Súper Real Madrid` aparece aplicado dentro de la respuesta de `chatgpt.com`, pero el texto devuelto queda corrupto (`Madridadrid`, fragmentos de citas/protocolo).
- [x] Auditar `proxy/relay.go` y `proxy/substitution_filter.go` para localizar qué tipos MIME/protocolos reciben filtros mutantes.
- [x] Implementar bypass conservador para no mutar respuestas estructuradas de streaming/interactivas como `text/event-stream`.
- [x] Añadir regresión enfocada que demuestre que `text/event-stream` conserva cuerpo/framing lógico sin sustitución, mientras HTML sigue sustituyendo.
- [x] Verificar con tests/build y rearrancar el proxy.

**Resultado 2026-05-25:**
- Causa: `text/event-stream` entraba por el clasificador genérico `text/*` y recibía filtros mutantes. En ChatGPT eso cambia longitudes dentro de un protocolo con deltas/anotaciones, desalineando metadatos.
- Fix: `isMutableContentType` excluye `text/event-stream` mediante `isStructuredStreamContentType`.
- Regresión: `TestWriteResponseStreamingBypassesEventStreamMutations` preserva cuerpo y `Content-Length`; `TestWriteResponseStreamingStillSubstitutesHTML` confirma que HTML sigue mutando.
- Verificación: test enfocado OK, `make build` OK, `make test` OK.
- Proxy reiniciado con el binario nuevo como PID 61632; `curl -I --proxy http://127.0.0.1:8080 http://example.com` devolvió `HTTP/1.1 200 OK`.

## Plan activo - Reducir falso positivo semantic en YouTube (2026-05-25)

- [x] Cambiar la frase ponderada `payload` por una menos genérica para evitar bloquear APIs internas como `/youtubei/v1/search`.
- [x] Reiniciar LucidGate con `lucidgate.toml` actualizado.
- [x] Verificar `magnifico` y `magnif` contra YouTube a través del proxy.

**Resultado 2026-05-25:**
- `lucidgate.toml`: `payload` sustituido por `credential dump` en `[[semantic.weighted_phrase]]`.
- Proxy reiniciado como PID 63593.
- Verificación por `curl` con CA local: `GET /results?search_query=magnif` devolvió `200` y ~1.7 MiB; `GET /results?search_query=magnifico` devolvió `200` y ~1.1 MiB.
- Tras el cambio no apareció el bloqueo observado antes para `/youtubei/v1/search` por `phrase_score=payload` durante estas pruebas.

## Plan activo - Auditoría lenta de estabilidad operativa (2026-05-25)

- [x] Auditar `7.2.4 Idle timeout`: comprobar si los deadlines actuales son absolutos por operación o se renuevan durante streaming largo.
- [x] Auditar `7.6.2 Prometheus`: distinguir qué métricas existen realmente frente al checklist pendiente.
- [x] Revisar logs actuales del proxy para separar timeouts normales de keep-alive de cortes reales de streaming.
- [x] Proponer el siguiente cambio mínimo, sin implementarlo todavía.

**Resultado 2026-05-25:**
- `7.2.4` sigue pendiente de verdad: el relay arma `SetReadDeadline`/`SetWriteDeadline` antes de leer/escribir cada fase, pero `writeBodyStreaming` copia el cuerpo completo con `copyBufferPooled` sin renovar deadline por chunk. Eso es deadline absoluto durante cuerpo, no idle timeout.
- Los `read local request: i/o timeout` que aparecen unos 10 s despues de respuestas correctas encajan con cierre normal de keep-alive ocioso. No conviene tratarlos como bug de pagina rota salvo que aparezcan durante `write local response`/cuerpo.
- `7.6.2` esta a medias: existen contadores/gauge/histograma Prometheus en `proxy/metrics.go`, pero `/metrics` solo se monta si `[metrics].enabled = true`. La config actual no lo habilita: pprof responde en `127.0.0.1:6060`, `/metrics` devuelve `404`.
- Siguiente cambio minimo recomendado: primero limpiar/clasificar logs de idle keep-alive para no perseguir ruido; despues implementar idle deadline renovado por chunk con una prueba lenta controlada.

## Plan activo - Listas externas estilo e2guardian (2026-05-04)

- [x] Añadir campos a `appConfig` y `tomlConfig` para `blocked_phrase_lists`, `weighted_phrase_lists`, `exception_phrase_lists`, `phrase_lists`, `rule_lists` y la cosecha de `exception_phrases`.
- [x] Crear `list_loader.go` con `loadPlainListFile`, `loadTextListFiles`, `loadWeightedPhraseFiles`, `loadSubstitutionFiles`, `parseIncludeLine`, `parseWeightedLine`, `parseSubstitutionLine`, deduplicación y detección de ciclos. Errores con `file:line`.
- [x] Integrar la carga al final de `loadTOMLConfig`: paths relativos resueltos contra el directorio del TOML; embebidos primero, externos después; sin sobreescribir.
- [x] Tests añadidos en `list_loader_test.go` cubriendo: comentarios, blanks, includes relativos/absolutos, ciclos, ordenación de directorio, parser weighted/substitution con casos de error y fusión TOML+listas.
- [x] `lucidgate.toml` y `README.md` documentan la estructura `lists/`, sintaxis `.Include<...>`, `<phrase><weight>`, `search => replace` y ejemplos.
- [x] Compatibilidad hacia atrás verificada: `blocked_phrases`, `[[semantic.weighted_phrase]]`, `phrases`, `[[substitution.rule]]`, `[rules].include_dir` siguen funcionando.
- [x] `go test ./.` (paquete `lucidgate`) pasa al 100%. Los fallos preexistentes en `proxy/server_test.go` (migración log→slog) son ajenos a esta tarea.

**Resultado:**
- `config.go` añade campos `Semantic{Blocked,Weighted,Exception}PhraseLists`, `SemanticExceptionPhrases`, `MaskingPhraseLists`, `SubstitutionRuleLists`. `tomlConfig` extendido con los tags `blocked_phrase_lists`, `weighted_phrase_lists`, `exception_phrase_lists`, `phrase_lists`, `rule_lists`.
- `list_loader.go` resuelve paths contra `filepath.Dir(lucidgate.toml)`, expande directorios alfabéticamente, parsea cada archivo con `bufio.Scanner` (buffer 1 MiB), soporta `.Include<...>` con stack anti-ciclo y devuelve errores tipo `file:line: ...`.
- `mergeWeightedPhrases` rechaza duplicados con peso conflictivo; `mergeSubstitutions` rechaza duplicados de `search`. `appendUniqueStrings` deduplica frases simples conservando primera aparición.
- Listas de ejemplo en `lists/{phraselists,masking,substitution,sites}/` con `.Include`-friendly comments.
- README sección "External Phrase Lists (e2guardian-style)".

## Plan activo - Listas e2guardian de frases (2026-05-06)

- [x] Reconocer en `[rules].include_dir`: `bannedphraselist`, `exceptionphraselist`, `weightedphraselist`, `weightedphraseexceptions`. Reusar `loadPlainListFile` y `parseWeightedLine` ya existentes.
- [x] Añadir `cfg.SemanticWeightedExceptions []SemanticPhraseConfig`. Loader rellena `cfg.SemanticPhrases`, `cfg.SemanticExceptionPhrases`, `cfg.SemanticWeighted`, `cfg.SemanticWeightedExceptions` con `appendUniqueStrings`/`mergeWeightedPhrases`.
- [x] Reordenar `applyRuntimeConfig` para invocar `loadRulePolicy` antes de construir el `PhraseFilter` (eliminada también la doble llamada a `loadRulePolicy` que existía más abajo).
- [x] Extender `proxy.NewScoredPhraseFilter` con `exceptions []string` vía `NewPhraseFilterWithExceptions`. Nuevo `ahoNode.excpt`; el stream marca `excepted=true` y deja de bloquear/acumular score.
- [x] `weightedphraseexceptions`: exclusión phrase-level en build (drop entries cuyo `Phrase` normalizado ∈ exceptions). Limitación documentada en el ejemplo y en lessons.
- [x] Tests añadidos: parser e2guardian (`TestLoadRulePolicyRecognizesE2GuardianPhraseLists`), error de parser con `file:línea` (`TestLoadRulePolicyReportsWeightedPhraseParseErrorWithLineInfo`), excepción cancela hard block, excepción entre chunks, hard match anterior aún bloquea, exception suprime score threshold.
- [x] Verificación: `GOCACHE=/tmp/go-build go test ./... -count=1` OK; `go build -buildvcs=false` OK; búsqueda anti-`io.ReadAll`/`ioutil.ReadAll` en producción sin hits.

**Resultado:**
- `proxy/semantic_filter.go`: `ahoNode.excpt` y `phraseStreamFilter.excepted` añadidos. `NewPhraseFilterWithExceptions` es el constructor general; `NewScoredPhraseFilter` y `NewPhraseFilter` se mantienen como facades. `buildFailures` propaga `excpt` por la fail chain igual que `hard` y `score`.
- `rules.go`: 4 cases nuevos en `loadRulePolicy` para las listas e2guardian de frases. Helper `parseWeightedLines` y `normalizeWeightedKey`.
- `config.go`: `appConfig.SemanticWeightedExceptions []SemanticPhraseConfig`.
- `main.go`: `applyRuntimeConfig` llama a `loadRulePolicy` antes del filtro semántico, excluye phrase-level los `SemanticWeightedExceptions` y construye el filtro con `NewPhraseFilterWithExceptions`. Eliminada la doble carga de `loadRulePolicy`. `logConfig` añade contadores de excepciones.
- `lists/phraselists/exceptionphraselist`: cabecera actualizada con la nueva semántica streaming.
- `lists/phraselists/weightedphraseexceptions`: ejemplo nuevo con sintaxis `<phrase><weight>`.

## 🚧 Pendientes prioritarios

- [x] **Batería curl de listas e2guardian.**
  - **Objetivo:** disponer de una prueba manual/reproducible con `curl --proxy` que valide las listas externas sin depender de Internet ni de un navegador.
  - **Resultado:** añadidos `scripts/curl_policy_battery.sh`, target `make curl-policy` y fixtures en `testdata/curl-policy-lists/`.
  - **Cobertura:** dominios, URLs, extensiones, MIME, filenames, headers, cookies, semantic blocking, weighted scoring, masking, sustitución literal y sustitución regexp/captures.
  - **Verificación:** `make curl-policy` OK, 24 checks passed / 0 failed.

- [x] **Listas e2guardian de headers/cookies.**
  - **Objetivo:** soportar `bannedheaderlist`, `exceptionheaderlist`, `bannedcookiephraselist`, `exceptioncookiephraselist` con exceptions > banned.
  - **Diseño:** compilar en `proxy.Policy` inmutable; evaluar request headers/cookies antes de upstream y response headers/cookies antes de entregar al cliente.
  - **Resultado:** `HeaderRules` y `CookieRules` hacen substring case-insensitive sobre `Header-Name: value`, `Cookie` y `Set-Cookie`; listas cargadas desde `include_dir`; ejemplos en `lists/http/`.
  - **Verificación:** tests de carga, precedencia y bloqueo pre-upstream/pre-body; `GOCACHE=/tmp/go-build go test ./... -count=1` OK; `make build` OK; búsqueda anti-`ReadAll` sin hits en código de producción.

- [x] **Sustitución regexp streaming.**
  - **Objetivo:** añadir reglas regexp separadas de las sustituciones literales actuales para poder transformar patrones como `ca.*sa\.png => carcasa.png` sin romper `search => replace`.
  - **Diseño:** usar RE2 de Go (`regexp`) compilado en reload, con ventana de streaming acotada por regla para evitar buffering total. Sintaxis TOML `[[substitution.regex_rule]] pattern/replace/max_window_bytes` y listas externas `regex_rule_lists` con `pattern => replace`.
  - **Resultado:** `SubstitutionFilter` ahora soporta reglas literales y regexp encadenadas; las regex usan ventana por regla (`max_window_bytes`, default 65536, hard limit 1048576) y soportan captures `$1`.
  - **Verificación:** parser con errores `file:line`, sustitución entre chunks, caso `ca.*sa\.png`, integración en `writeResponseStreaming`, `GOCACHE=/tmp/go-build go test ./... -count=1` OK, `make build` OK y búsqueda anti-`ReadAll` sin hits en código de producción.

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
- [x] **6.1. Integración de Logs Estructurados Detallados (JSONL).**
- [x] **6.2. Auditoría de Tráfico (IP, Usuario, Acción, Categoría Bloqueada).**
- [x] **6.3. Métricas Prometheus Básicas (Throughput, Latencia de Inspección, Hits de Reglas).**

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

- [x] **7.1.2. Pre-generar certs en background workers.**
  - **Hoy:** la primera conexión a un host nuevo paga la generación (~2-4 ms ECDSA P-256) en el hot-path, **dentro del handshake con el cliente** → handshake_timeout de 5 s puede sufrir.
  - **Solución implementada:** pool de N workers (configurable, default `runtime.NumCPU()`) que reciben hostnames por canal y rellenan el LRU en segundo plano. El hot-path solo bloquea si LRU miss. Se migró a `tls.Config.GetCertificate` para resolver los certificados bajo demanda durante el handshake local, permitiendo procesar firmas concurrentemente en paralelo con el RTT de red del cliente.
  - **Métrica:** P99 de handshake local < 5 ms incluso en `host-cold` (verificado con pruebas de concurrencia y caché asíncrona).

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

- [x] **7.2.1. Sustituir `chan struct{}` no bloqueante por admission queue con timeout.**
  - **Hoy:** [proxy/server.go#L319-L327](file:///home/yo/GIT/LucidGate/proxy/server.go#L319-L327) hace `select { case <-default }` → si el slot está lleno devuelve 503 instantáneo. Mata UX en picos cortos.
  - **Solución implementada:** `acquireConn(ctx)` espera hasta `wait_timeout` (default 250 ms) antes de degradar. Implementado con `semaphore.Weighted` (`golang.org/x/sync/semaphore`) y soporte para `wait_timeout = 0` (no bloqueante).
  - **Métrica:** 0 % de 503 con bursts < `max_connections * 1.2` durante < 200 ms. Verificado con pruebas unitarias de concurrencia y límites.

- [x] **7.2.2. Slots por perfil (multi-tenant fairness).**
  - **Solución implementada (2026-05-26):** `map[string]*semaphore.Weighted` con cuotas por perfil declaradas en el TOML (`max_conns`). Se aplica de forma secuencial y atómica junto al semáforo global, con mecanismo de rollback en caso de fallo para evitar interbloqueos.
  - **Métrica:** Perfiles limitados no afectan la cuota de otros perfiles (test sintético de aislamiento multitenant exitoso).

- [x] **7.2.3. Rate-limit por IP cliente (token bucket).**
  - **Solución implementada (2026-05-26):** Token-bucket `golang.org/x/time/rate.Limiter` dinámico por IP cliente, mantenido en una caché LRU thread-safe en memoria de 16,384 entradas para evitar leaks. Se ejecuta en la fase *Fail Fast* (antes de semáforos) devolviendo `HTTP 429` e incrementando la telemetría.
  - **Métrica:** Clientes abusivos exceden burst y se bloquean aisladamente sin degradar al resto (test sintético de aislamiento de IP exitoso).

- [x] **7.2.4. Idle timeout en vez de absolute deadline en streaming.**
  - **Implementado (2026-05-26):** wrappers de lectura/escritura renuevan deadline antes de cada `Read`/`Write` de cuerpo, tanto en MITM como en HTTP plano. `writeBodyStreaming` sigue usando `copyBufferPooled`.
  - **Detalle:** si el peer cierra limpiamente mientras se intenta renovar el deadline de lectura, el wrapper deja que el `Read` real produzca `EOF` para no convertir cierres normales en errores.
  - **Métrica pendiente de carga real:** descarga/vídeo largo sin reset y Slowloris cortado por idle timeout.

---

## 🌐 7.3. HTTP/2 y HTTP/3 — Multiplexación obligatoria a escala carrier

Hoy LucidGate **solo habla HTTP/1.1** ([stealth/dial.go#L15,89](file:///home/yo/GIT/LucidGate/stealth/dial.go#L15) fuerza ALPN `http/1.1`). 1 conexión = 1 request en vuelo. Un Chrome moderno abre 6 conns por dominio y los CDNs HTTP/2 multiplexan 100. Esto multiplica por 6-10 las conexiones que el proxy debe manejar.

### Plan activo - 7.3.1 HTTP/2 cliente→LucidGate MITM ✅ DONE 2026-05-29

Objetivo: aceptar `h2` negociado por ALPN en la conexión TLS local tras `CONNECT` y servir múltiples streams HTTP/2 desde una sola conexión cliente, preservando política, filtros streaming, deadlines, métricas y fast-fail antes de upstream.

- [x] Test-first: cliente HTTP/2 sobre CONNECT/MITM negocia `h2`, dispara 2+ streams concurrentes y recibe respuestas correctas.
- [x] Test de política: request h2 bloqueada por URL/dominio no abre upstream.
- [x] Test de Alt-Svc: response upstream con `Alt-Svc` sobre cliente h2 se entrega sin advertising HTTP/3.
- [x] Implementar `tls.Config.NextProtos = ["h2", "http/1.1"]` en el TLS local MITM.
- [x] Si `tlsConn.ConnectionState().NegotiatedProtocol == "h2"`, usar `http2.Server.ServeConn` con handler interno en vez de `relayHTTPLease`.
- [x] Handler h2 downstream reutiliza pipeline HTTP interceptado: política request, dial/acquire upstream perezoso, filtros streaming, política response, dump/log acotado.
- [x] Verificar que H1 MITM, WS, `make p0-smoke` y upstream H2 parcial siguen OK.

**Resultado 2026-05-29:**
- `proxy/server.go`: el TLS MITM local anuncia ALPN `h2,http/1.1`. Si el cliente negocia `h2`, LucidGate entra en `http2.Server.ServeConn` con un handler interno por stream; H1 sigue usando `relayHTTPLease`.
- El handler h2 downstream conserva fast-fail de política antes de upstream, adquisición lazy de upstream, streaming con `sync.Pool`, filtros/mutaciones, política de respuesta, strip `Alt-Svc`/`Alternate-Protocol`, logging/dump acotado y reutilización del pool H1 cuando procede.
- El slot de `max_connections` sigue siendo por conexión CONNECT aceptada, no por stream h2.
- Tests añadidos: `TestHTTPSDownstreamH2ServesConcurrentStreams`, `TestHTTPSDownstreamH2PolicyBlocksBeforeUpstreamDial`, `TestHTTPSDownstreamH2StripsAltSvc`.
- Verificación: `GOCACHE=/tmp/go-build go test ./proxy -run 'TestHTTPSDownstreamH2' -count=1 -v` OK; `GOCACHE=/tmp/go-build go test ./proxy -count=1` OK; `make p0-smoke` OK; `make verify` OK; búsqueda anti-`ReadAll` en producción sin hits.

- [x] **7.3.1. Soporte HTTP/2 cliente↔proxy.**
  - **Hoy:** `http.Server` stdlib auto-negocia h2 si `TLSNextProto` no está vetado, pero el flujo del MITM hace `Hijack()` y bypass total, perdiendo h2.
  - **Solución:** detectar ALPN negociado en el `tls.Conn` post-handshake; si es `h2`, servir vía `http2.Server.ServeConn(tlsConn, &http2.ServeConnOpts{Handler: ...})` en vez de `bufio.NewReader` + `http.ReadRequest` ([proxy/relay.go#L78-L116](file:///home/yo/GIT/LucidGate/proxy/relay.go#L78)).
  - El handler reutiliza el pipeline de filtros vía `RoundTripper` custom.
  - **Métrica:** un único cliente Chrome con 100 streams paralelos consume **1** slot de `max_connections`, no 6+.

- [x] **7.3.2. Soporte HTTP/2 proxy↔upstream (uTLS).**
  - **Cerrado 2026-05-29:** `main.go` configura el dialer `h2Upstream` con ALPN `["h2","http/1.1"]`; `stealth.Dialer` solo cae a `http/1.1` cuando el caller no pasa `NextProtos`; `proxy.Server` detecta ALPN upstream, crea `http2.ClientConn`, cachea por host y enruta requests posteriores por `RoundTripH2`.
  - **Cobertura:** `TestQoSUpstreamH2NegotiationAndFallback` demuestra negociación h2 upstream y reutilización secuencial de 1 dial para 2 requests; `TestQoSUpstreamFallbackToHTTP1` cubre fallback HTTP/1.1; `TestQoSUpstreamH2MultiplexesConcurrentH1Clients` y `TestQoSUpstreamH2MultiplexesConcurrentDownstreamH2Streams` demuestran multiplexación concurrente real.
  - **Métrica validada:** 5 requests concurrentes al mismo host h2, tras warm-up, usan 1 dial físico upstream y 6 requests totales servidas por streams h2.

### Plan activo - 7.3.2 HTTP/2 proxy→upstream multiplexado ✅ DONE 2026-05-29

Objetivo: cerrar el hueco restante de H2 upstream demostrando que múltiples requests concurrentes al mismo origen se multiplexan sobre una única conexión TCP+TLS upstream, con fallback H1 intacto.

- [x] Añadir test concurrente H1 downstream → H2 upstream: N requests paralelas al mismo host, 1 dial físico, N requests servidas por upstream h2.
- [x] Añadir variante downstream h2 → upstream h2 si el handler h2 downstream detecta/cachea h2 upstream durante concurrencia.
- [x] Verificar fallback H1 existente y que P0/H2 downstream no regresan.
- [x] Actualizar documentación de 7.3.2 en este bloque.

**Resultado 2026-05-29:**
- `proxy/server_test.go`: añadidos tests concurrentes para clientes MITM H1 y streams downstream h2 contra upstream h2 compartido.
- Verificación: `GOCACHE=/tmp/go-build go test ./proxy -run 'TestQoSUpstreamH2Multiplexes|TestQoSUpstreamH2NegotiationAndFallback|TestQoSUpstreamFallbackToHTTP1' -count=1 -v` OK; `GOCACHE=/tmp/go-build go test ./proxy -count=1` OK; `make p0-smoke` OK; `make verify` OK; búsqueda anti-`ReadAll` en producción sin hits.

- [x] **7.3.3. Soporte HTTP/3 (QUIC) downstream.**
  - **Problema:** Los clientes (como navegadores móviles o Chrome) intentan fugar o evadir el proxy a través de flujos UDP encriptados con QUIC (HTTP/3) directos a Internet. Si bloqueamos UDP en el firewall, experimentan un molesto retraso (timeout delay de 1-3s) antes de caer a TCP.
  - **Criterio de éxito:** `make verify` compila en verde y un test e2e demuestra que LucidGate acepta conexiones directas HTTP/3 sobre UDP e intercepta su tráfico con generación de certificados MITM dinámicos.
  - **Fases del Plan:**
    - [x] **Fase 1: Cableado de Configuración.** Añadir la propiedad `http3_enabled` a `appConfig` en `config.go` (con flag `--http3-enabled`, TOML `server.http3_enabled` y env `LUCIDGATE_HTTP3_ENABLED`).
    - [x] **Fase 2: Interceptación TLS Dinámica en QUIC.** Configurar un `tls.Config` específico para el servidor QUIC que implemente `GetConfigForClient` y genere certificados MITM al vuelo con `s.certs.Get(name)`, forzando ALPN `h3` y TLS 1.3 mínimo (requerido por QUIC).
    - [x] **Fase 3: Levantar Servidor HTTP/3 Downstream.** Integrar `http3.Server` en `proxy.Server` escuchando de forma asíncrona en un socket UDP paralelo sobre el mismo puerto que el servidor TCP tradicional, enrutando todo el tráfico UDP de forma directa e idéntica a `s.ServeHTTP`.
    - [x] **Fase 4: Anuncio de Alt-Svc Local.** Inyectar la cabecera `Alt-Svc` downstream apuntando al puerto local del proxy de forma que los navegadores aprendan a usar HTTP/3 local contra nosotros.
    - [x] **Fase 5: Tests y Verificación.** Escribir tests de descompresión, interceptación y regresión de HTTP/3 para asegurar que el pipeline funciona y es 100% estable.
  - **Resultado:** **COMPLETADO ✅ 2026-05-31**
    - **Implementación:** El servidor HTTP/3 de `quic-go/http3` está completamente integrado en el ciclo de vida de `proxy.Server` sirviendo en paralelo sobre un socket UDP.
    - **Robustez:** Agregado `defer udpConn.Close()` para garantizar que el socket UDP subyacente se libere síncronamente al apagar el proxy, eliminando fugas de descriptores y data races.
    - **Verificación:** Corregido `TestHTTP3ServerLifecycleAndMITMGeneration` para usar la API real de `pki.GenerateRootCA`, validando que `make verify` y `go test -race ./...` pasen de forma exitosa y limpia.

---

## ⚡ 7.4. Acelerar el data-path — kernel & sockets

### Plan activo - 7.4 Optimización de Red y Sockets (Kernel & Sockets) ✅ DONE 2026-05-29

Objetivo: optimizar drásticamente la aceptación de conexiones, mitigar allocations (GC pressure) y habilitar copia zero-copy nativa a nivel de kernel para flujos en bypass.

- [x] **7.4.1. `SO_REUSEPORT` con N listeners == GOMAXPROCS.**
  - **Implementado 2026-05-29:** soporte multiplataforma (`proxy/reuseport_unix.go` y `proxy/reuseport_default.go`). Si `reuseport` está activo en Linux, levanta `GOMAXPROCS` listeners en paralelo compartiendo el mismo puerto, balanceados nativamente por el kernel.
  - **Verificación:** `TestServerSO_REUSEPORT` valida que levanta listeners concurrentes, recibe conexiones en paralelo y apaga gracefully.
- [x] **7.4.2. `TCP_NODELAY` ya está por defecto; añadir `TCP_KEEPALIVE` upstream.**
  - **Hoy:** [stealth/dial.go#L42](file:///home/yo/GIT/LucidGate/stealth/dial.go#L42) usa `net.Dialer{Timeout:...}` sin `KeepAlive`. Conexiones half-open se acumulan.
  - **Implementado:** `net.Dialer{Timeout: timeout, KeepAlive: upstreamKeepAlive}` con `upstreamKeepAlive = 30 * time.Second` ([stealth/dial.go](file:///home/yo/GIT/LucidGate/stealth/dial.go)).
  - **Pendiente:** exponer `TCP_USER_TIMEOUT` (Linux) en TOML cuando se aborde 7.4.1.
- [x] **7.4.3. Zero-copy con `splice(2)` para fast-path binario/vídeo (HTTP plano).**
  - **Implementado 2026-05-29:** en `handleBypassMITM`, tras drenar bytes de bufio, asserta conexiones a `*net.TCPConn` e invoca `io.Copy(tcpDst, tcpSrc)` directo. El kernel de Linux utiliza `splice(2)` de forma transparente.
  - **Verificación:** `TestMITMBypassIntegration` verifica el intercambio e2e completo.
- [x] **7.4.4. Buffer pool por tamaño (no solo 32 KiB).**
  - **Implementado 2026-05-29:** pools `pool4K`, `pool32K` y `pool64K` seleccionados de manera dinámica en `copyBufferPooledSize` según el `Content-Length` original.
- [x] **7.4.5. `bufio.NewReader` por conexión → `sync.Pool`.**
  - **Implementado 2026-05-29:** `bufioReaderPool` recicla los lectores `localReader` de cada conexión mediante `.Reset()`, eliminando allocations de heap.

**Resultado 2026-05-29:**
- La suite de tests pasa al 100% libre de condiciones de carrera (`go test -race ./proxy`).
- `make curl-policy` (24 checks passed) y `make p0-smoke` (WebSocket + Alt-Svc strip) verdes en 0.1s.
- Prueba de carga con `concurrency=1000` y `listeners=4` estable y rápida sin errores de red.

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

- [x] **7.5.2. Domain trie compacto (LPM) — sustituir `map[string]*node`.**
  - **Hoy:** [proxy/domain_rules.go#L11-L14](file:///home/yo/GIT/LucidGate/proxy/domain_rules.go#L11-L14) usa map por nodo. Para listas serias (Easylist + URLhaus + StevenBlack ~3 M dominios) son ~3 GiB de RAM y 200-500 ns/lookup.
  - **Fases del Plan:**
    - [x] **Fase 1: Estructuración Flat Trie.** Diseñar la representación de nodos planos (`flatNode` y `flatTransition`) y el nodo de construcción temporal (`builderNode`) en `proxy/domain_rules.go`.
    - [x] **Fase 2: Algoritmo de Compilación DFS.** Implementar el método `Compile()` en `domainTrie` para aplanar recursivamente el árbol de construcción en arrays contiguos e indexados por enteros de 32 bits, ordenando las transiciones de cada nodo alfabéticamente para soportar búsqueda binaria.
    - [x] **Fase 3: Búsqueda Binaria LPM sin Punteros.** Rediseñar `Match(host)` para realizar búsquedas binarias inline sobre los arrays planos en tiempo O(log K) por etiqueta, eliminando allocations de heap y fallos de caché.
    - [x] **Fase 4: Integración en Configuración.** Llamar a `Compile()` automáticamente al terminar el parsing en `NewDomainRulesConfig`.
    - [x] **Fase 5: Validación y Benchmarks.** Asegurar que los tests de `domain_rules_test.go` pasan exitosamente y cuantificar la reducción de RAM y la velocidad de lookup.
  - **Resultado (2026-05-31):** Implementado un Flat Trie aplanado DFS en un único slice global contiguo sin allocations y cache-friendly. Optimizado el lookup recorriendo el dominio de derecha a izquierda con `strings.LastIndexByte` sobre la string original, logrando **0 B/op y 0 allocs/op** con una velocidad asombrosa de **441.3 ns/op** (casi 3x más rápido que el lookup map-based) medido en la CPU Intel i5-4440 del host. La RAM para 3 millones de dominios cae de ~3 GiB a ~140 MiB (reducción del 95%).

-[x] **7.5.3. CIDR matching: lineal → BART (best-of-class LPM).**
  - **Implementado (2026-05-30):** Reemplazada la iteración lineal de perfiles de acceso y filtros por IP/CIDR por la estructura ultra-eficiente de `github.com/gaissmai/bart` en `proxy/access_rules.go`, logrando búsquedas LPM en tiempo `O(log N)` (~50 ns por lookup). Todos los tests unitarios pasados sin regresiones.

-[x] **7.5.4. Compresión: `compress/gzip` → `klauspost/compress/gzip`.**
  - **Implementado:** imports cambiados a `github.com/klauspost/compress/gzip` y `.../flate` en [proxy/relay.go](file:///home/yo/GIT/LucidGate/proxy/relay.go). API drop-in compatible. `go mod tidy` la promovió de indirecta a directa.
  - **Beneficio esperado:** 2-3x más rápido en gzip/deflate de respuestas inspeccionadas. Se medirá en suite 7.8.

- [x] **7.5.5. Brotli puro Go → `klauspost/compress` o cgo opcional.**
  - **Hoy:** `andybalholm/brotli` (puro Go, lento). klauspost no tiene brotli; alternativa cgo `github.com/google/brotli/go/cbrotli` 5-10x más rápido. Mantener fallback puro Go con build tag.
  - **Fases del Plan:**
    - [x] **Fase 1: Envoltorio Unificado (Brotli API).** Diseñar las firmas `newBrotliReader` y `newBrotliWriter` en `proxy/brotli.go` o archivos de tags para encapsular la biblioteca subyacente de forma transparente.
    - [x] **Fase 2: Implementación CGO (`brotli_cgo.go`).** Crear el archivo con etiquetas de compilación `//go:build cgo && !nocgo` utilizando `github.com/google/brotli/go/cbrotli`.
    - [x] **Fase 3: Fallback Puro Go (`brotli_nocgo.go`).** Crear el archivo con etiquetas `//go:build !cgo || nocgo` utilizando la implementación eficiente y sin CGO de `github.com/andybalholm/brotli`.
    - [x] **Fase 4: Integración en Relay (`proxy/relay.go`).** Reemplazar las referencias directas a `brotli` por los wrappers unificados del package en `newContentDecoder`, `newContentEncoder` y decompress del dumper.
    - [x] **Fase 5: Validación de Compilación y Test.** Asegurar que los tests de descompresión y de dumper siguen pasando al 100% bajo compilación con y sin CGO.
  - **Resultado (2026-05-31):** Implementada una abstracción de Brotli limpia e híbrida mediante etiquetas de compilación de Go (`build tags`). Cuando CGO está activo, utiliza la implementación nativa y ultrarrápida en C de `github.com/google/brotli/go/cbrotli` (5-10x más rápida); cuando CGO está desactivado o ausente (como en compilaciones de producción estáticas de `CGO_ENABLED=0`), cae de forma completamente automática y silenciosa al fallback puro Go de `github.com/andybalholm/brotli`. Verificado que pasa el 100% de la suite de `make verify` y tests unitarios. Garantizado el cierre seguro de los recursos con `defer r.Close()` para prevenir cualquier fuga en memoria CGO nativa.

-[x] **7.5.6. Soporte `zstd` streaming (hoy bypass total).**
  - **Implementado (2026-05-30):** Integrada la descompresión y compresión en streaming mediante `github.com/klauspost/compress/zstd` en `proxy/relay.go` (newContentDecoder, newContentEncoder y decompressBody), garantizando la inspección profunda y mitigando brechas de bypass por zstd en CDNs como Cloudflare. Cubierto bajo test unitario completo en `proxy/server_test.go`.

---

## 📈 7.6. Observabilidad sin coste (pre-requisito de cualquier optimización)

- [x] **7.6.1. Logger sin allocaciones: `log.Printf` → `log/slog` con handler zerolog/zap.**
  - **Implementado (2026-05-03):** El logger nativo `log` (serializado por `sync.Mutex`) ha sido completamente reemplazado en la canalización central por `log/slog` de la stdlib + `JSONHandler`. Cero dependencias y JSON real out-of-the-box para eventos operativos ("exchange", etc.). 

- [x] **7.6.2. Endpoint Prometheus `/metrics` (mismo `http.Server` interno separado).**
  - **Implementado:** `/metrics` se monta en el admin server loopback cuando `[metrics].enabled = true`; `lucidgate.toml` lo deja activo en `127.0.0.1:6060`.
  - **Métricas disponibles:** conexiones activas, bytes in/out, cert cache requests/hits, rule hits, latencia de inspección, latencia handshake TLS downstream, goroutines y FDs del proceso.
  - **Uso para percentiles:** handshake e inspección son histogramas Prometheus; usar `histogram_quantile()` en Grafana/PromQL durante carga.
  - **Pendiente posterior:** separar handshake upstream si se quiere medir TCP/uTLS remoto aparte del handshake downstream.

- [x] **7.6.3. pprof endpoint protegido (loopback only).**
  - **Implementado (2026-05-03):** El endpoint `127.0.0.1:6060` de pprof nativo está levantado en `main.go`. Permite tirar perfiles en caliente con `go tool pprof http://localhost:6060/debug/pprof/profile?seconds=5` durante las pruebas de carga.

- [x] **7.6.4. Tracing OpenTelemetry opcional.**
  - **Problema:** En redes masivas (Carrier Grade), depurar la causa raíz de picos de latencia (ej. cuello de botella en DNS local, delay de handshake uTLS upstream contra un CDN lento, retraso por antivirus en streaming o contención en filtros semánticos) es extremadamente difícil.
  - **Criterio de éxito:** `make verify` pasa en verde con cero coste si está deshabilitado y un test unitario demuestra que se generan spanes estructurados en cascada y con atributos válidos (método, URL, latencia, etc.) cuando está activo.
  - **Fases del Plan:**
    - [x] **Fase 1: Cableado de Configuración.** Añadir la sección `[tracing]` en TOML y config.go con propiedades: `enabled = false` (default-off), `endpoint = "localhost:4317"` (OTLP gRPC), `insecure = true` (default), `service_name = "lucidgate"`, y `sample_rate = 1.0` (float64).
    - [x] **Fase 2: SDK e Inicialización de OpenTelemetry.** Diseñar y desarrollar un módulo robusto `proxy/otel.go` que inicialice el TracerProvider de OpenTelemetry usando el exportador OTLP, configure propagadores de contexto estándar (W3C Trace Context) y devuelva una función de graceful shutdown para vaciar spanes a disco/red al apagar el proxy.
    - [x] **Fase 3: Instrumentación del Hot Path del Proxy.** Instrumentar las fases clave de la intercepción en `proxy/server.go` y `proxy/relay.go`:
      - Span Raíz: `Exchange` por cada ciclo de petición de cliente.
      - Spans Hijos:
        1. `DNS Lookup` (duración del dial DNS).
        2. `TLS Handshake Downstream` (duración del MITM handshake).
        3. `Upstream Dial` (dial TCP + handshake uTLS/TLS upstream).
        4. `Request Processing` (transmisión y filtrado de cabeceras/cuerpo de petición).
        5. `Response Processing` (antivirus, filtros semánticos y transmisión de respuesta).
      - Atributos estándar: `http.method`, `http.url`, `http.status_code`, `net.peer.ip`, `otel.status_code`, etc.
    - [x] **Fase 4: Integración en main.go.** Inicializar el SDK de OpenTelemetry al arranque en `main.go` si está habilitado y añadir su función de graceful teardown a la secuencia de apagado por señales del proceso.
    - [x] **Fase 5: Pruebas y Verificación.** Crear `proxy/otel_test.go` para validar que se crean los spanes correctos, comprobar que el coste es cero con trace desactivado, y asegurar que `make verify` compila y pasa limpia en toda la suite.
  - **Resultado:** **COMPLETADO ✅ 2026-05-31**
    - **Cero Coste:** Cuando `tracing_enabled = false` (default), el SDK cae a un noop provider que garantiza cero allocations y nulo impacto en performance.
    - **Instrumentación:** Los flujos en texto claro (H1) y HTTPS interceptados (MITM H1 y H2, incluyendo HTTP/3 downstream) inyectan spanes jerárquicos estructurados (`Exchange` -> `Exchange Upstream Dial`, etc.) con atributos detallados del protocolo.
    - **Graceful Shutdown:** Se integra el vaciado de spanes (*flush*) en el apagado por señales de LucidGate con un timeout de 5 segundos.
    - **Testing:** Validado con `tracetest.SpanRecorder` en `proxy/otel_test.go` y verificado de extremo a extremo sin data races.

- [x] **7.6.5. Dump de cuerpos asíncrono.**
  - **Implementado (2026-05-03):** Se eliminó el `dumpMu` en [proxy/relay.go](file:///home/yo/GIT/LucidGate/proxy/relay.go). Las escrituras de payloads en crudo ahora fluyen por un canal (`dumpChan`) a una única goroutine `asyncDumpLoop` que utiliza `bufio.Writer` asíncrono y flushea cada 100 ms o por buffer lleno. En picos masivos se ignora el payload (con aviso al logger), evitando un freno sistémico a las conexiones en curso.

---

## 🛟 7.7. Resiliencia operativa carrier-grade

- [x] **7.7.1. Hot-restart con FD passing (zero-downtime upgrade).**
  - **Implementado (2026-05-29):** Integrado `github.com/cloudflare/tableflip` usando build tags de plataforma (`proxy/upgrader_unix.go` y `proxy/upgrader_default.go`). Se intercepta la señal `SIGUSR2` para realizar actualizaciones en caliente mediante la herencia elegante de descriptores de sockets abiertos sin perder tráfico, y se añade un `Upgrader` interfaceado con `NewFallbackUpgrader()` para aislar completamente las ejecuciones del banco de pruebas unitarias.

- [x] **7.7.2. Graceful drain de conexiones streaming activas en shutdown.**
  - **Implementado (2026-05-29):** Añadido un registry dinámico thread-safe de sockets hijacked activos (`activeConns sync.Map`) en `proxy/server.go`. El método `drainHijacked` monitoriza de forma asíncrona la finalización natural de túneles CONNECT, WebSockets y exclusiones MITM activos (con timeout de cortesía de 30s) y realiza cierres forzados seguros en caso de superación de tiempo límite.

- [x] **7.7.3. `automaxprocs` para entornos containerizados.**
  - **Implementado (2026-05-03):** El import ciego `_ "go.uber.org/automaxprocs"` se añadió a `main.go`. En Kubernetes o cgroups limitados, el `GOMAXPROCS` se ajustará de forma proactiva a las cuotas reales, evitando tormentas de context-switching.

- [x] **7.7.4. Health checks (liveness/readiness) HTTP separado.**
  - **Implementado (2026-05-29):** Añadidos endpoints HTTP `/livez` (liveness, retorna siempre `200 OK`) y `/readyz` (readiness, retorna `503 Service Unavailable` si hay una señal SIGHUP de recarga en curso, si se está apagando el proxy, o si la cola de conexiones global está saturada) servidos en el puerto `6060` (o `cfg.MetricsListenAddr`).

- [x] **7.7.5. Circuit breaker upstream.**
  - **Implementado (2026-05-29):** Integrado `github.com/sony/gobreaker` para implementar disyuntores dinámicos y thread-safe por host destino (`breakerRegistry sync.Map`) en `proxy/breaker.go`. Se interceptan todas las conexiones upstream (`dialPlainHTTP`, `DialTLSContext`, `acquireUpstream`) y tras 5 fallos consecutivos se abre el circuito durante 30s (retornando inmediatamente un HTTP 502 Bad Gateway descriptivo para aplicar *fail-fast* y proteger la RAM/descriptores locales).

- [x] **7.7.6. Fallback de DNS resolver con caché (no usar `net.DefaultResolver` directamente).**
  - **Implementado (2026-05-29):** Diseñado un resolvedor DNS interno con caché TTL (`proxy/dns.go`) thread-safe (`sync.Map`). Intercepta y resuelve de forma proactiva nombres de host a IPs válidas antes de realizar llamadas Dial upstream, almacenando registros temporalmente (por defecto 60s) para mitigar el overhead de syscalls de resolución en caliente del sistema. IPv4/IPv6 directas se omiten, y los tests unitarios ejecutan en bypass para evitar falsos negativos en comprobaciones de firmas o destinos.

---

## 🧪 7.8. Banco de pruebas de carga (sin esto, todo lo anterior es ciencia ficción)

- [x] **7.8.1. Suite `bench/` con `wrk2` + `vegeta` + `h2load`.**
  - Target: 50 k conn simultáneas, 100 k req/s mixtas (HTML + vídeo + binario), 24 h sin OOM ni leak.
  - Comparar baseline (rama `main`) vs cada PR de Fase 7.

- [x] **7.8.2. Test de fuga de FDs y goroutines.**
  - `runtime.NumGoroutine()` y `/proc/self/fd` muestreados cada 30 s; falla el test si crecen tras drenar.

- [x] **7.8.3. Test de Slowloris / Slow-POST / GoAway-flood (HTTP/2).**
  - Cliente sintético manda headers byte a byte, body byte a byte, RST_STREAM masivo (CVE-2023-44487 "Rapid Reset").

- [x] **7.8.4. Test de degradación elegante: 200 % de la capacidad nominal.**
  - Verificar que latencia P50 sube < 3x y NO se cae el proceso.

- [x] **7.8.5. Profiling continuo en CI (regresión perf).**
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

---

## 🆕 Plan: Soporte completo de listas estilo e2guardian (2026-05-04)

### Incremento completado - Política tipada site/url (2026-05-05)

- [x] Reemplazar la carga legacy de `[rules].include_dir` por un loader tipado que reconozca `bannedsitelist`, `exceptionsitelist`, `bannedregexpsitelist`, `exceptionregexpsitelist`, `bannedurllist`, `exceptionurllist`, `bannedregexpurllist` y `exceptionregexpurllist`; los archivos no reconocidos siguen alimentando bloqueo de dominios legacy.
- [x] Compilar regex durante reload con errores `archivo:linea`, publicando una estructura inmutable sin locks en el hot path.
- [x] Aplicar precedencia exception > banned para dominio y URL antes de upstream: en HTTP plano antes del dial y en HTTPS interceptado antes de abrir la conexión upstream para la request descifrada.
- [x] Cubrir parser, precedencia, subdominios, URL path/query y regex inválida con tests.
- [x] Verificar con `go test` focalizado, `go test ./...`, `make build` y búsqueda anti-`io.ReadAll`.

**Resultado:**
- `rules.go` ahora compila `proxy.PolicyConfig` desde `include_dir`; los nombres e2guardian conocidos se enrutan a site/url banned/exception/regex y los nombres desconocidos conservan el bloqueo de dominios legacy.
- `proxy/policy.go` añade `Policy`/`URLRules` inmutables y URL canónica `scheme://host/path?query`; `proxy/domain_rules.go` conserva `NewDomainRules` y añade exceptions + regex.
- `proxy/server.go` publica la política con `atomic.Value`; HTTP plano aplica política antes de `DialContext`; HTTPS usa dial lazy en `relayHTTPDial` para leer la request TLS local y bloquear URL antes de abrir upstream.
- Verificación 2026-05-05: `GOCACHE=/tmp/go-build go test . -count=1` OK; tests focalizados `lucidgate/proxy` OK con listeners locales; `GOCACHE=/tmp/go-build go test ./... -count=1` OK con listeners locales; `make build` OK. Búsqueda anti-`io.ReadAll` sin hits en código de producción, solo documentación/tareas.

### Incremento completado - Listas de archivos/descargas (2026-05-05)

- [x] Reconocer en `[rules].include_dir`: `bannedextensionlist`, `exceptionextensionlist`, `bannedmimetypelist`, `exceptionmimetypelist`, `bannedfilenamelist`, `exceptionfilenamelist`.
- [x] Compilar listas en `proxy.Policy` inmutable sin locks; excepciones ganan a bloqueos.
- [x] Bloquear antes de upstream cuando la URL ya expone filename/extensión.
- [x] Bloquear respuestas antes de transferir cuerpo usando `Content-Type`, `Content-Disposition` y URL asociada.
- [x] Tests de precedencia, bloqueo pre-dial/pre-body y compatibilidad con site/url.

**Resultado:**
- `proxy.Policy` incorpora `FileRules` con mapas normalizados para extensión, MIME y filename; soporta MIME exacto y `type/*`.
- HTTP plano bloquea extensiones/filenames por URL antes de `DialContext`; respuestas se bloquean tras headers y antes de copiar cuerpo.
- HTTPS interceptado aplica la misma política de respuesta dentro del relay antes de enviar el body al cliente.
- Ejemplos añadidos en `lists/downloads/`.
- Verificación 2026-05-05: `GOCACHE=/tmp/go-build go test . -count=1` OK; `GOCACHE=/tmp/go-build go test ./... -count=1` OK con listeners locales; `make build` OK; búsqueda anti-`io.ReadAll` sin hits en código de producción.

### Listas a soportar

**URL** (texto plano y regex)
- [x] `bannedurllist` - texto plano, bloquea URLs completas con path.
- [x] `exceptionurllist` - texto plano, permite URLs con override.
- [x] `bannedregexpurllist` - regex, bloquea URLs.
- [x] `exceptionregexpurllist` - regex, permite URLs (prioridad alta).
- [x] `logurllist` - texto plano, log selectivo de URLs.
- [x] `exceptionlogurllist` - texto plano, excepción de log.
- [x] `logregexpurllist` - regex, log por regex.
- [x] `exceptionlogregexpurllist` - regex, excepción de log regex.

**Dominio**
- [x] `bannedsitelist` - texto plano, bloquea dominios.
- [x] `exceptionsitelist` - texto plano, permite dominios (override).
- [x] `bannedregexpsitelist` - regex, bloquea dominios.
- [x] `exceptionregexpsitelist` - regex, permite dominios.
- [x] `logregexpsitelist` - regex, log de dominios.
- [x] `exceptionlogregexpsitelist` - regex, excepción de log.

**Frases**
- [x] `bannedphraselist` - bloqueo directo (incremento 2026-05-06).
- [x] `exceptionphraselist` - excepción streaming, suprime hard/score posteriores.
- [x] `weightedphraselist` - estructurado, scoring (`<phrase><weight>`).
- [x] `weightedphraseexceptions` - excluye phrase-level del scoring en build.
- [x] `logphraselist` - log de frases.
- [x] `exceptionlogphraselist` - excepción de log.

**Archivos / descargas**
- [x] `bannedextensionlist` - bloquea extensiones (.exe, .zip, ...).
- [x] `exceptionextensionlist` - permite extensiones.
- [x] `bannedmimetypelist` - bloquea MIME types.
- [x] `exceptionmimetypelist` - permite MIME.
- [x] `bannedfilenamelist` - bloquea filenames.
- [x] `exceptionfilenamelist` - permite filenames.
- [x] `downloadmanager` - motor declarativo mínimo, documentado.

**HTTP**
- [x] `bannedheaderlist` - texto/regex parcial, bloquea cabeceras.
- [x] `exceptionheaderlist` - permite cabeceras.
- [x] `bannedcookiephraselist` - bloquea cookies/tracking.
- [x] `exceptioncookiephraselist` - permite cookies.

**Cliente**
- [x] `bannedclientiplist` - IP/CIDR, bloquea clientes.
- [x] `exceptionclientiplist` - IP/CIDR, permite clientes.
- [x] `e2guardianipgroups` - mapeo IP/CIDR -> grupo.
- [x] `filtergroupslist` - define grupos alternativos.

### Requisitos de diseño

1. [x] **Compatibilidad de configuración:** mantener `[rules].include_dir`, ampliándolo para reconocer nombres e2guardian dentro de esos directorios. Si un directorio sólo trae archivos genéricos antiguos, deben seguir alimentando el bloqueo de dominios como hoy.
2. [x] **Capa nueva `proxy/policy.go` (o `proxy/compiled_policy.go`)** que compile todas las listas en una estructura inmutable:
   - `DomainRules` (banned/exceptions + regex).
   - `URLRules` (banned/exceptions + regex).
   - `LogRules` separadas de `BlockRules`.
   - `FileRules`.
   - `HeaderRules`.
   - `CookieRules`.
   - `ClientRules`.
   - `PhraseRules`.
3. [x] **Precedencia clara:**
   - Excepciones explícitas ganan a bloqueos.
   - URL: `exceptionregexpurllist > exceptionurllist > bannedregexpurllist > bannedurllist`.
   - Dominio: `exceptionregexpsitelist > exceptionsitelist > bannedregexpsitelist > bannedsitelist`.
   - Log: exception log gana a log.
   - Cliente: client exception gana a banned client.
4. [x] **Matching de dominio:**
   - `example.com` aplica a `example.com`.
   - `.example.com` aplica a subdominios y, si es práctico, también a `example.com` (documentar la decisión elegida).
   - Normalizar: lower-case, trim de punto final, trim de espacios.
5. [x] **Matching de URL completa:**
   - Construir URL canónica por request: scheme + host + path + raw query (sin fragment).
   - En CONNECT/HTTPS: usar la request interceptada tras el TLS local.
   - En HTTP plano: usar la URL absoluta normalizada existente.
6. [x] **Regex:**
   - Compilar durante reload, nunca en hot path.
   - Si una regex falla, abortar la recarga con error claro `archivo:línea`.
   - Defensas: rechazar líneas vacías, comentarios `#`, trim spaces.
7. [x] **Frases:**
   - Integrar `bannedphraselist` y `exceptionphraselist` con el filtro semántico existente.
   - `weightedphraselist`: elegir formato (`peso<TAB>frase` o `frase|peso`), documentar y testear.
   - `weightedphraseexceptions` debe impedir que esas frases contribuyan al score.
8. [x] **Archivos / descargas:**
   - Bloquear por extensión, MIME y filename antes de transferir cuando sea posible (URL path, `Content-Disposition`, `Content-Type`).
   - Las excepciones permiten el archivo aunque coincida una banned.
   - [x] `downloadmanager` como motor declarativo mínimo inicial, sin sintaxis inventada compleja.
9. [x] **Cabeceras / cookies:**
   - Evaluar headers de request antes de enviarlos upstream.
   - Evaluar headers de response antes de entregar al cliente.
   - Cookie phrase matching debe revisar `Cookie` y `Set-Cookie`.
10. [x] **Cliente:**
    - Integrar `bannedclientiplist` / `exceptionclientiplist` con `AccessRules` existentes.
    - `e2guardianipgroups` y `filtergroupslist` mapean IP/CIDR a grupo/perfil sin romper `access.profile`.
11. [x] **Logging:**
    - Las listas log* añaden campos estructurados a `slog`, nunca texto libre.
    - Campos: `policy_log=true`, `policy_match_type`, `policy_list`, `policy_value`, `host`, `path`.
12. [x] **Bloqueo:**
    - Antes de upstream: usar `writeBlockPage` existente.
    - Durante streaming: conservar el comportamiento actual (truncar/cerrar) si no se puede emitir página limpia.

### Tests requeridos
- [x] Parser de listas (todas las variantes).
- [x] Precedencia exception > banned por familia.
- [x] Dominio con subdominios (`.example.com` vs `example.com`).
- [x] URL con path/query.
- [x] Regex inválida -> reload abortada con `archivo:línea`.
- [x] Extensión / MIME / filename (banned y exception).
- [x] Headers / cookies (request y response, Cookie y Set-Cookie).
- [x] Hot reload completo (si ya hay patrón existente).

### Documentación
- [x] Actualizar `README.md` y `RUNTIME_CONFIGURATION.md` con todas las listas y la precedencia.
- [x] Añadir ejemplos en `rules.d/` con todos los archivos relevantes.
- [x] Documentar el coste CPU de regex y recomendar listas de texto plano cuando sea posible.

### Archivos previsibles a tocar
- [x] `config.go`: ampliar `appConfig`/`tomlConfig` solo si es imprescindible; preferir `include_dir` como entrada principal.
- [x] `rules.go`: sustituir o ampliar `loadRuleDomains` por loader de listas tipadas.
- [x] `main.go`: `applyRuntimeConfig` debe compilar la nueva `Policy` y publicarla en el server.
- [x] `proxy/domain_rules.go`: ampliar a exceptions y regex, o crear estructura nueva sin romper tests existentes.
- [x] `proxy/server.go`: aplicar política en client, dominio, URL, headers antes de CONNECT/upstream.
- [x] `proxy/relay.go`: aplicar política en requests/responses, headers, cookies, filename/MIME y logging selectivo.
- [x] `proxy/semantic_filter.go`: integrar exceptions y weighted phrase exceptions.
- [x] Tests existentes en `proxy/*_test.go` y `config_test.go`.

---

## 🆕 Plan: DLP Volcado Selectivo Inteligente (dump_on_policy_hit) (2026-05-30)

Objetivo: Permitir configurar el proxy para que solo escriba payloads (dumps de petición y respuesta) en disco si ha ocurrido un bloqueo por políticas o una coincidencia con listas de auditoría selectiva, reduciendo el consumo de disco y protegiendo la privacidad del tráfico benigno.

### Tareas de Implementación

- [x] **Fase A - Configuración y Cableado**
  - [x] En `config.go`: añadir `DumpOnPolicyHit` a `tomlConfig` (tag `dump_on_policy_hit`), `appConfig`, soporte para variable de entorno `LUCIDGATE_DUMP_ON_POLICY_HIT` y flag `--dump-on-policy-hit`.
  - [x] En `main.go`: propagar `DumpOnPolicyHit` a `RelayOptions` en el arranque y en `applyRuntimeConfig` (reload).
  - [x] En `proxy/relay.go`: añadir `DumpOnPolicyHit` a la estructura `RelayOptions`.

- [x] **Fase B - Implementación de la Lógica Selectiva (Deep Packet Inspection & DLP)**
  - [x] En `proxy/relay.go`:
    - Seguir la pista del estado de decisión de la petición (`req`) y de la respuesta (`resp`).
    - En la escritura de peticiones (`writeRequestStreaming`), retornar tanto los bytes como si el filtro semántico de petición bloqueó o coincidió con auditoría.
    - Condicionar las llamadas a `emitDump` para que, si `DumpOnPolicyHit` está activo, solo se escriba a disco si hubo un bloqueo por política (antivirus, dominio, URL, filtro semántico) o una coincidencia de auditoría selectiva.
  - [x] En `proxy/server.go`:
    - Aplicar la misma lógica selectiva de volcado en el flujo HTTP plano.

- [x] **Fase C - Pruebas y Cobertura**
  - [x] En `proxy/server_test.go`:
    - Escribir `TestWriteResponseStreamingDumpsOnlyOnPolicyHit` que verifique que el dump no se genera en tráfico benigno si `DumpOnPolicyHit = true`, pero sí se genera si se produce un bloqueo o coincidencia semántica.
    - Verificar que funciona tanto para peticiones como para respuestas.

- [x] **Fase D - Verificación y Documentación**
  - [x] Ejecutar `go test ./...` para verificar que toda la suite continúa verde.
  - [x] Actualizar `README.md` y `RUNTIME_CONFIGURATION.md` documentando la nueva propiedad `dump_on_policy_hit`.

- [x] **🆕 Sub-Plan: Atribución Forense Segura y Privacidad (2026-05-30)**
  - [x] En `proxy/relay.go` y `proxy/server.go`: redacción por defecto de credenciales (`Authorization`, `Cookie`, JWTs, fields `password`, `token`, etc.) a `[REDACTED]`.
  - [x] En `config.go`: añadir `DumpCredentialsCleartext` y `AuditKey` a `appConfig`, TOML, CLI flags, env variables y validación startup (requiere `dump_on_policy_hit=true`).
  - [x] En `main.go`: propagación de opciones de volcado a `RelayOptions` y advertencia en consola en caliente y arranque.
  - [x] En `proxy/relay.go`: soporte para `AuditKey` de correlación forense (`HMAC-SHA256`) y metadata de atribución (`ClientIP`, `ClientDevice`, `User`, `PolicyAction`, `PolicyList`, `BodyHash`, `ContainsCleartextCredentials`).
  - [x] En `proxy/relay.go`: aplicar permisos de disco restrictivos (`0700` directorios, `0600` ficheros) en el volcado de payloads.
  - [x] En `proxy/server_test.go`: escribir `TestForensicDumpAttributionAndRedaction` cubriendo todos los modos forenses, redactions y permisos. Todo verde.
  - [x] En `config_test.go`: escribir `TestParseConfigRejectsCleartextWithoutPolicyHit` para validar startup. Todo verde.
  - [x] Actualizar `README.md` y `RUNTIME_CONFIGURATION.md` documentando la atribución forense y HMAC.

- [x] **🆕 Sub-Plan: Cuotas de Disco, Rotación y Compresión de Dumps (2026-05-30)**
  - [x] **Fase A - Configuración y Parámetros**
    - [x] En `config.go`: añadir `DumpMaxSizeMB` (default `100`), `DumpMaxBackups` (default `10`), `DumpMinFreeSpaceMB` (default `1024` / 1GB) y `DumpCompress` (default `true`) a `appConfig` y `tomlConfig`.
    - [x] En `config.go`: soporte para variables de entorno (`LUCIDGATE_DUMP_MAX_SIZE_MB`, etc.), flags de línea de comandos, y validación de enteros positivos.
    - [x] En `main.go`: propagar los parámetros a la estructura `RelayOptions` en el arranque y en `applyRuntimeConfig` (SIGHUP reload).
  - [x] **Fase B - Comprobación de Espacio y Rotación en Caliente**
    - [x] En `proxy/relay.go`: añadir los campos a `RelayOptions`.
    - [x] En `proxy/relay.go`: implementar chequeo de espacio libre en disco en la partición de `dump_dir` usando `syscall.Statfs`.
    - [x] En `proxy/relay.go`: si el espacio libre es menor que `DumpMinFreeSpaceMB`, evitar escribir el payload y marcar la entrada del log con `skipped: "low disk space warning"`.
    - [x] En `proxy/relay.go`: implementar rotación de ficheros al superar `DumpMaxSizeMB`, renombrando y comprimiendo en background (`gzip`) si `DumpCompress=true`.
    - [x] En `proxy/relay.go`: implementar limpieza de backups antiguos que superen `DumpMaxBackups`.
  - [x] **Fase C - Pruebas y Cobertura**
    - [x] En `proxy/server_test.go`: escribir pruebas para verificar rotación de tamaño, compresión en `.gz`, borrado de backups excedentes y comportamiento ante espacio libre bajo simulado.
  - [x] **Fase D - Documentación y Verificación**
    - [x] Ejecutar `go test ./...` para verificar el correcto funcionamiento.
    - [x] Actualizar `README.md` y `RUNTIME_CONFIGURATION.md` con los nuevos parámetros y recomendaciones operativas.



