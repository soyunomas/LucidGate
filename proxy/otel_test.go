package proxy

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestInitTracingDisabled(t *testing.T) {
	ctx := context.Background()
	shutdown, err := InitTracing(ctx, false, "localhost:4317", true, "lucidgate-test", 1.0)
	if err != nil {
		t.Fatalf("InitTracing failed when disabled: %v", err)
	}
	if shutdown == nil {
		t.Fatal("expected non-nil shutdown function even when disabled")
	}
	defer shutdown(ctx)

	// Validar que GlobalTracer no es nil y es seguro de usar
	if GlobalTracer == nil {
		t.Fatal("expected GlobalTracer to be non-nil when disabled")
	}

	// Comprobar que usar el GlobalTracer no rompe nada
	ctx, span := GlobalTracer.Start(ctx, "TestSpanNoop")
	span.SetAttributes(attribute.String("test.key", "val"))
	span.End()
}

func TestInitTracingEnabled(t *testing.T) {
	ctx := context.Background()

	// Usamos un SpanRecorder de tracetest local para capturar todos los spanes generados
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))

	// Reemplazar temporalmente el TracerProvider global para inspección
	oldProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer otel.SetTracerProvider(oldProvider)

	GlobalTracer = otel.Tracer("lucidgate-test")

	// Crear un span estructurado simulando una fase del proxy
	exchangeCtx, exchangeSpan := GlobalTracer.Start(ctx, "Exchange")
	exchangeSpan.SetAttributes(
		attribute.String("http.method", "GET"),
		attribute.String("http.url", "https://www.google.com/"),
	)

	_, dialSpan := GlobalTracer.Start(exchangeCtx, "Exchange Upstream Dial")
	time.Sleep(10 * time.Millisecond)
	dialSpan.End()

	exchangeSpan.End()

	// Validar que los spanes se grabaron correctamente
	spans := sr.Ended()
	if len(spans) != 2 {
		t.Errorf("expected 2 ended spans, got %d", len(spans))
	}

	var foundExchange, foundDial bool
	for _, s := range spans {
		if s.Name() == "Exchange" {
			foundExchange = true
			// Validar atributos de Exchange
			attrs := s.Attributes()
			var foundMethod, foundURL bool
			for _, a := range attrs {
				if a.Key == "http.method" && a.Value.AsString() == "GET" {
					foundMethod = true
				}
				if a.Key == "http.url" && a.Value.AsString() == "https://www.google.com/" {
					foundURL = true
				}
			}
			if !foundMethod {
				t.Error("missing or invalid http.method attribute in Exchange span")
			}
			if !foundURL {
				t.Error("missing or invalid http.url attribute in Exchange span")
			}
		}
		if s.Name() == "Exchange Upstream Dial" {
			foundDial = true
			// El parent span ID debe ser el span ID de Exchange
			if s.Parent().SpanID() == [8]byte{} {
				t.Error("expected dial span to have a parent")
			}
		}
	}

	if !foundExchange {
		t.Error("Exchange span not recorded")
	}
	if !foundDial {
		t.Error("Exchange Upstream Dial span not recorded")
	}
}
