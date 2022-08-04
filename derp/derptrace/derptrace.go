package derptrace

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.8.0"
)

func InitTracing(ctx context.Context, collectorAddr string, hostname string, sampleRate float64) (func(context.Context) error, error) {
	exporter, err := exporter(ctx, collectorAddr)
	if err != nil {
		return nil, fmt.Errorf("unable to create exporter: %w", err)
	}

	res, err := resource.New(ctx, resource.WithAttributes(
		semconv.ServiceNamespaceKey.String("derpers"),
		semconv.ServiceNameKey.String(hostname),
	))
	if err != nil {
		return nil, fmt.Errorf("unable to create resource: %w", err)
	}

	tracerProvider := sdktrace.NewTracerProvider(
		// TODO: configure in some manner
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(sampleRate)),
		// Traces are sent in batches. The defaults are:
		// The maximum queue size is 2048. If this is reached, spans are
		// dropped.
		// Spans are sent, regardless of the queue size being reached, after 5000ms.
		// Exports time out after 3000ms
		// The maximum batch size is 512. Multiple batches of spans are sent sequentially.
		// BlockOnQueueFull - we don't use this.
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	return tracerProvider.Shutdown, nil
}

// exporter is a http opentelementry exporter
func exporter(ctx context.Context, collectorAddr string) (*otlptrace.Exporter, error) {
	var opts []otlptracehttp.Option
	if collectorAddr == "" {
		opts = append(opts, otlptracehttp.WithInsecure())
	} else {
		opts = append(opts, otlptracehttp.WithTLSClientConfig(nil), otlptracehttp.WithEndpoint(collectorAddr))
	}

	exporter, err := otlptrace.New(ctx,
		otlptracehttp.NewClient(
			opts...,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create http trace exporter: %w", err)
	}

	return exporter, nil
}
