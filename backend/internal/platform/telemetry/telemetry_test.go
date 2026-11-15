package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestHTTPSpansUseRoutePatterns(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer otel.SetTracerProvider(prev)

	inner := http.NewServeMux()
	inner.HandleFunc("GET /api/v1/findings/{id}", func(w http.ResponseWriter, r *http.Request) {
		if TraceID(r.Context()) == "" {
			t.Error("trace id should be available to handlers (log correlation)")
		}
		w.WriteHeader(204)
	})
	outer := http.NewServeMux()
	// A middleware that copies the request (like the auth middleware) sits
	// between the muxes; the innermost pattern must still win.
	outer.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		RecordRoute(inner).ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), struct{}{}, 1)))
	}))
	h := HTTP(RecordRoute(outer), "pathos")
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/findings/0190c0de-1234", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/healthz", nil))

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("want 1 span (health checks filtered), got %d", len(spans))
	}
	if spans[0].Name() != "GET /api/v1/findings/{id}" {
		t.Errorf("span name = %q", spans[0].Name())
	}
	found := false
	for _, a := range spans[0].Attributes() {
		if a.Key == "http.route" && a.Value.AsString() == "/api/v1/findings/{id}" {
			found = true
		}
	}
	if !found {
		t.Error("http.route attribute missing")
	}
}

func TestSetupNoEndpointIsNoop(t *testing.T) {
	shutdown, err := Setup(context.Background(), "", "api", "test", "x")
	if err != nil || shutdown(context.Background()) != nil {
		t.Fatal("no-op setup failed")
	}
}
