package proxy

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
)

// GlobalTracer is the tracer used across the LucidGate codebase.
// Defaults to a noop tracer when tracing is disabled.
var GlobalTracer trace.Tracer = otel.Tracer("lucidgate-noop")

// InitTracing initializes the OpenTelemetry TracerProvider and registers
// OTLP exporter, text propagators, and samplers. Returns a graceful
// shutdown function to flush pending spans on exit.
func InitTracing(ctx context.Context, enabled bool, endpoint string, insecure bool, serviceName string, sampleRate float64) (func(context.Context) error, error) {
	if !enabled {
		GlobalTracer = otel.Tracer("lucidgate-noop")
		return func(context.Context) error { return nil }, nil
	}

	// 1. Create resources standard telemetry descriptors
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create otel resource: %w", err)
	}

	// 2. Configure OTLP gRPC exporter
	var secureOption otlptracegrpc.Option
	if insecure {
		secureOption = otlptracegrpc.WithInsecure()
	} else {
		secureOption = otlptracegrpc.WithTLSCredentials(nil)
	}

	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(endpoint),
		secureOption,
	}

	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create otlp gRPC exporter: %w", err)
	}

	// 3. Configure sampling rate
	var sampler sdktrace.Sampler
	if sampleRate >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else if sampleRate <= 0.0 {
		sampler = sdktrace.NeverSample()
	} else {
		sampler = sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sampleRate))
	}

	// 4. Configure TracerProvider with batch processor
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sampler),
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	GlobalTracer = otel.Tracer("lucidgate")

	shutdownFunc := func(shutdownCtx context.Context) error {
		return tp.Shutdown(shutdownCtx)
	}

	return shutdownFunc, nil
}
