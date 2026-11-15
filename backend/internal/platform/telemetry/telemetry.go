// Package telemetry wires OpenTelemetry traces and metrics (OTLP/HTTP).
// Export is enabled by OTEL_EXPORTER_OTLP_ENDPOINT; the standard OTEL_*
// variables (headers, sampler, protocol paths) are honoured by the SDK.
package telemetry

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Setup installs global providers when endpoint is set and returns a
// shutdown function that flushes them. With no endpoint it is a no-op.
func Setup(ctx context.Context, endpoint, role, version, instance string) (func(context.Context) error, error) {
	if endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		attribute.String("service.name", "pathos-"+role),
		attribute.String("service.namespace", "pathos"),
		attribute.String("service.version", version),
		attribute.String("service.instance.id", instance),
	))
	if err != nil {
		return nil, err
	}
	texp, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, err
	}
	mexp, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(texp), sdktrace.WithResource(res))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(mexp, sdkmetric.WithInterval(30*time.Second))))
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	if err := runtime.Start(runtime.WithMeterProvider(mp)); err != nil {
		return nil, err
	}
	return func(ctx context.Context) error {
		return errors.Join(tp.Shutdown(ctx), mp.Shutdown(ctx))
	}, nil
}

type routeKey struct{}

type routeHolder struct{ pattern string }

// HTTP instruments a handler: a server span per request and the standard
// HTTP server metrics. Spans and metrics carry the matched route pattern
// (recorded by RecordRoute), never raw paths with IDs.
func HTTP(next http.Handler, operation string) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := &routeHolder{}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), routeKey{}, h)))
		if h.pattern == "" {
			return
		}
		method, route, ok := strings.Cut(h.pattern, " ")
		if !ok {
			method, route = r.Method, h.pattern
		}
		span := trace.SpanFromContext(r.Context())
		span.SetName(method + " " + route)
		span.SetAttributes(attribute.String("http.route", route))
		if l, ok := otelhttp.LabelerFromContext(r.Context()); ok {
			l.Add(attribute.String("http.route", route))
		}
	})
	return otelhttp.NewHandler(inner, operation,
		otelhttp.WithFilter(func(r *http.Request) bool { return r.URL.Path != "/healthz" && r.URL.Path != "/readyz" }))
}

// RecordRoute wraps a ServeMux so the pattern it matched is recorded for
// HTTP. With nested muxes the innermost (most specific) match wins.
func RecordRoute(mux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r) // ServeMux sets r.Pattern on this request
		if h, ok := r.Context().Value(routeKey{}).(*routeHolder); ok && h.pattern == "" && r.Pattern != "" {
			h.pattern = r.Pattern
		}
	})
}

// TraceID returns the current trace ID for log correlation ("" if none).
func TraceID(ctx context.Context) string {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		return sc.TraceID().String()
	}
	return ""
}
