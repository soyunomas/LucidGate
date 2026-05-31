# Plan de Trabajo - Fase 6: Observabilidad Enterprise y Listas de Log

Este listado detalla los pasos para dotar a LucidGate de observabilidad empresarial y el soporte de listas de logs e2guardian.

## 📋 Tareas de Implementación

- [x] **Fase 1: Instalación de Dependencias e Instrumentación**
  - [x] Ejecutar `go get github.com/prometheus/client_golang` y sincronizar con `go mod tidy`.
  - [x] Crear el fichero `proxy/metrics.go` con las definiciones de métricas de Prometheus.
  - [x] Exponer callbacks globales en `pki/leaf.go` (`OnCacheRequest` y `OnCacheHit`) y cablearlos en `main.go`.
  - [x] Añadir telemetría de conexiones activas en `proxy/server.go:ServeHTTP`.
  - [x] Añadir registro de histograma de latencias al procesar chunks en `InspectReader` (en `proxy/relay.go`).

- [x] **Fase 2: Listas de Log e2guardian**
  - [x] Añadir campos de `Log` y `LogRules` en `proxy/policy.go` para compilar e identificar reglas de logging.
  - [x] Actualizar Aho-Corasick (`proxy/semantic_filter.go`) para registrar el string de frases que causen match (añadiendo `.phrase` en `ahoNode` y propagando en BFS).
  - [x] Actualizar `rules.go` y `config.go` para parsear y almacenar todas las nuevas listas `log*` y `exceptionlog*`.

- [x] **Fase 3: Integración de Servidor de Administración y Auditoría**
  - [x] Actualizar `main.go` para levantar el servidor HTTP de administración (exponiendo `/metrics` y `pprof`).
  - [x] Actualizar `logExchange` y bloqueos en `proxy/relay.go` para enriquecer los logs con campos `policy_log=true` o suprimir logs según corresponda (mitigando caídas por valores negativos de bytes leídos).

- [x] **Fase 4: Verificación y Pruebas**
  - [x] Escribir pruebas unitarias para `LogRules` y el parser de configuración en `list_loader_test.go`.
  - [x] Escribir pruebas unitarias y de contexto para la coincidencia observadora/no-bloqueante de frases de log.
  - [x] Asegurar que `go test ./...` y `make curl-policy` pasan al 100%.
