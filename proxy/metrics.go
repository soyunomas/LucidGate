package proxy

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	ActiveConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "lucidgate_active_connections",
		Help: "Number of active concurrent connections being served by LucidGate.",
	})
	BytesTransferred = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "lucidgate_bytes_total",
		Help: "Total bytes transferred through the proxy.",
	}, []string{"direction"}) // "in", "out"
	CertCacheRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "lucidgate_cert_cache_requests_total",
		Help: "Total certificate requests processed by LeafCache.",
	})
	CertCacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "lucidgate_cert_cache_hits_total",
		Help: "Total certificate cache hits in LeafCache.",
	})
	RuleHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "lucidgate_rule_hits_total",
		Help: "Total policy and filtering rule hits in LucidGate.",
	}, []string{"profile", "policy_list", "action"}) // profile, policy_list (bannedsitelist, logurllist, bannedphraselist, etc.), action (block, log)
	InspectionDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "lucidgate_inspection_duration_seconds",
		Help:    "Duration of content inspections in seconds.",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
	})
	TLSHandshakeDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "lucidgate_tls_handshake_duration_seconds",
		Help:    "Duration of TLS handshakes handled by LucidGate.",
		Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
	}, []string{"direction"}) // "downstream" for browser-side MITM handshakes.
	ConnectionsRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "lucidgate_connections_rejected_total",
		Help: "Total connections rejected by LucidGate.",
	}, []string{"reason"}) // "max_connections", etc.
	CertGenerationDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "lucidgate_cert_generation_duration_seconds",
		Help:    "Duration of certificate generations in seconds.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
	})
	AltSvcStripped = promauto.NewCounter(prometheus.CounterOpts{
		Name: "lucidgate_alt_svc_stripped_total",
		Help: "Total upstream responses from which an HTTP/3 advertising header (Alt-Svc or Alternate-Protocol) was removed.",
	})
	WebSocketSessions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "lucidgate_websocket_sessions_total",
		Help: "Total WebSocket Upgrade sessions handled by LucidGate.",
	}, []string{"result"}) // "opened", "denied", "error", "upstream_refused"
	WebSocketBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "lucidgate_websocket_bytes_total",
		Help: "Total bytes transferred over WebSocket sessions.",
	}, []string{"direction"}) // "in" (client->upstream), "out" (upstream->client)
	RequestSubstitutionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "lucidgate_request_substitutions_total",
		Help: "Total request body substitutions performed by LucidGate.",
	}, []string{"kind"}) // "literal", "regex"
	RequestSubstitutionSkippedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "lucidgate_request_substitution_skipped_total",
		Help: "Total requests skipped for body substitution.",
	}, []string{"reason"}) // "framing", etc.
	AlertsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "lucidgate_alerts_total",
		Help: "Total policy alerts triggered by LucidGate.",
	}, []string{"category"})
	DroppedLogsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "lucidgate_dropped_logs_total",
		Help: "Total exchange logs dropped due to full queue.",
	}, []string{"sink"}) // "access", "alert"
)
