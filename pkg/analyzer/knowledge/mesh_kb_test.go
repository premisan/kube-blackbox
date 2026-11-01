package knowledge

import (
	"testing"
)

func TestAnalyzeMeshLogs_EnvoyUOFlag(t *testing.T) {
	logs := `
[2026-11-02T01:00:00.123Z] "POST /api/v1/checkout HTTP/1.1" 503 UO 0 120 1 - "-" "Go-http-client/1.1" "req-12345" "checkout-service.prod:8080"
`
	res := AnalyzeMeshLogs(logs)
	if res == nil {
		t.Fatalf("expected non-nil MeshAnalysisResult")
	}
	if res.MatchedFlag != "UO" {
		t.Errorf("expected flag UO, got %q", res.MatchedFlag)
	}
	if res.RootCause != "EnvoyCircuitBreakerOverflow" {
		t.Errorf("expected EnvoyCircuitBreakerOverflow, got %q", res.RootCause)
	}
	if res.SummaryKo == "" || res.SuggestedFixKo == "" {
		t.Errorf("expected non-empty localized summary and fix")
	}
}

func TestAnalyzeMeshLogs_EnvoyUHFlag(t *testing.T) {
	logs := `
[2026-11-02T01:00:00.123Z] "GET /items HTTP/1.1" 503 UH 0 19 0 - "-" "curl/7.68.0" "req-999" "item-service:80"
`
	res := AnalyzeMeshLogs(logs)
	if res == nil {
		t.Fatalf("expected non-nil MeshAnalysisResult")
	}
	if res.MatchedFlag != "UH" {
		t.Errorf("expected flag UH, got %q", res.MatchedFlag)
	}
	if res.RootCause != "EnvoyNoHealthyUpstream" {
		t.Errorf("expected EnvoyNoHealthyUpstream, got %q", res.RootCause)
	}
}

func TestAnalyzeMeshLogs_NginxEmerg(t *testing.T) {
	logs := `
2026/11/02 01:00:00 [emerg] 1#1: invalid number of arguments in "set" directive in /etc/nginx/conf.d/default.conf:42
nginx: [emerg] invalid number of arguments in "set" directive in /etc/nginx/conf.d/default.conf:42
`
	res := AnalyzeMeshLogs(logs)
	if res == nil {
		t.Fatalf("expected non-nil MeshAnalysisResult")
	}
	if res.RootCause != "NginxConfigSyntaxError" {
		t.Errorf("expected NginxConfigSyntaxError, got %q", res.RootCause)
	}
	if res.NginxLine != 42 || res.NginxConfFile != "/etc/nginx/conf.d/default.conf" {
		t.Errorf("expected /etc/nginx/conf.d/default.conf:42, got %s:%d", res.NginxConfFile, res.NginxLine)
	}
}

func TestAnalyzeMeshLogs_NginxBodyTooLarge(t *testing.T) {
	logs := `
2026/11/02 01:00:00 [error] 23#23: *1024 client intended to send too large body: 52428800 bytes, client: 10.244.1.1, server: api.domain.com
`
	res := AnalyzeMeshLogs(logs)
	if res == nil {
		t.Fatalf("expected non-nil MeshAnalysisResult")
	}
	if res.RootCause != "NginxClientBodySizeExceeded" {
		t.Errorf("expected NginxClientBodySizeExceeded, got %q", res.RootCause)
	}
	if res.PayloadSize != 52428800 {
		t.Errorf("expected 52428800 bytes, got %d", res.PayloadSize)
	}
}

func TestAnalyzeMeshLogs_Istio15021Ready(t *testing.T) {
	logs := `
curl: (7) Failed to connect to 127.0.0.1 port 15021: Connection refused
Envoy proxy is not ready yet
`
	res := AnalyzeMeshLogs(logs)
	if res == nil {
		t.Fatalf("expected non-nil MeshAnalysisResult")
	}
	if res.RootCause != "IstioProxyNotReady" {
		t.Errorf("expected IstioProxyNotReady, got %q", res.RootCause)
	}
}

func TestAnalyzeMeshLogs_IstioMTLS(t *testing.T) {
	logs := `
[2026-11-02 01:00:00.000][15][debug][connection] [source/common/network/connection_impl.go:123] remote address: 10.244.2.14:443
[2026-11-02 01:00:00.000][15][error][connection] [source/common/tls/ssl_socket.cc:200] SSL: error:100000f7:SSL routines:OPENSSL_internal:WRONG_VERSION_NUMBER
`
	res := AnalyzeMeshLogs(logs)
	if res == nil {
		t.Fatalf("expected non-nil MeshAnalysisResult")
	}
	if res.RootCause != "IstioStrictMTLSMismatch" {
		t.Errorf("expected IstioStrictMTLSMismatch, got %q", res.RootCause)
	}
}

func TestAnalyzeMeshLogs_EnvoyGatewayNack(t *testing.T) {
	logs := `
2026-11-02T01:00:00.000Z ERROR translation failed to translate HTTPRoute default/my-route: BackendRef service/missing-svc not found
NACK received from envoy for type.googleapis.com/envoy.config.route.v3.RouteConfiguration
`
	res := AnalyzeMeshLogs(logs)
	if res == nil {
		t.Fatalf("expected non-nil MeshAnalysisResult")
	}
	if res.RootCause != "EnvoyGatewayTranslationFailed" {
		t.Errorf("expected EnvoyGatewayTranslationFailed, got %q", res.RootCause)
	}
}
