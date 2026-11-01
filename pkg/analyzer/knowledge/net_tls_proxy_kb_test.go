package knowledge

import (
	"testing"
)

func TestAnalyzeNetTLSProxyLogs_SquidAuth(t *testing.T) {
	logs := `HTTP/1.1 407 Proxy Authentication Required
Server: squid/5.7
MIME-Version: 1.0
Proxy-Authenticate: Basic realm="Squid proxy-caching web server"
Connection: close`

	res := AnalyzeNetTLSProxyLogs(logs)
	if res == nil {
		t.Fatalf("expected NetTLSProxyAnalysis, got nil")
	}
	if res.RootCause != "ProxyAuthenticationRequired" {
		t.Fatalf("expected ProxyAuthenticationRequired, got %s", res.RootCause)
	}
}

func TestAnalyzeNetTLSProxyLogs_SquidAccessDenied(t *testing.T) {
	logs := `HTTP/1.1 403 Forbidden
Server: squid/5.7
The following error was encountered while trying to retrieve the URL: https://internal.company.com/api
Access Denied by Squid ACL.
Generated Mon, 02 Nov 2026 02:00:00 GMT by proxy.corp (squid/5.7)`

	res := AnalyzeNetTLSProxyLogs(logs)
	if res == nil {
		t.Fatalf("expected NetTLSProxyAnalysis, got nil")
	}
	if res.RootCause != "ProxyAccessDeniedACL" {
		t.Fatalf("expected ProxyAccessDeniedACL, got %s", res.RootCause)
	}
}

func TestAnalyzeNetTLSProxyLogs_SquidDNSFail(t *testing.T) {
	logs := `HTTP/1.1 502 Bad Gateway
Server: squid/5.7
The following error was encountered while trying to retrieve the URL: http://invalid-domain-xyz.internal/
DNS name lookup failure (ERR_DNS_FAIL)`

	res := AnalyzeNetTLSProxyLogs(logs)
	if res == nil {
		t.Fatalf("expected NetTLSProxyAnalysis, got nil")
	}
	if res.RootCause != "ProxyDNSResolutionFailed" {
		t.Fatalf("expected ProxyDNSResolutionFailed, got %s", res.RootCause)
	}
}

func TestAnalyzeNetTLSProxyLogs_TLSUnknownCA_Java(t *testing.T) {
	logs := `javax.net.ssl.SSLHandshakeException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
    at java.base/sun.security.ssl.Alert.createSSLException(Alert.java:131)
    at java.base/sun.security.ssl.TransportContext.fatal(TransportContext.java:371)`

	res := AnalyzeNetTLSProxyLogs(logs)
	if res == nil {
		t.Fatalf("expected NetTLSProxyAnalysis, got nil")
	}
	if res.RootCause != "TLSUntrustedCA" {
		t.Fatalf("expected TLSUntrustedCA, got %s", res.RootCause)
	}
}

func TestAnalyzeNetTLSProxyLogs_TLSUnknownCA_Go(t *testing.T) {
	logs := `Get "https://10.96.0.1:443/api/v1/namespaces": x509: certificate signed by unknown authority`

	res := AnalyzeNetTLSProxyLogs(logs)
	if res == nil {
		t.Fatalf("expected NetTLSProxyAnalysis, got nil")
	}
	if res.RootCause != "TLSUntrustedCA" {
		t.Fatalf("expected TLSUntrustedCA, got %s", res.RootCause)
	}
}

func TestAnalyzeNetTLSProxyLogs_TLSHostMismatch(t *testing.T) {
	logs := `Get "https://10.0.0.15:8443": x509: certificate is valid for api.example.com, not 10.0.0.15`

	res := AnalyzeNetTLSProxyLogs(logs)
	if res == nil {
		t.Fatalf("expected NetTLSProxyAnalysis, got nil")
	}
	if res.RootCause != "TLSHostnameMismatch" {
		t.Fatalf("expected TLSHostnameMismatch, got %s", res.RootCause)
	}
}

func TestAnalyzeNetTLSProxyLogs_TCPConnReset(t *testing.T) {
	logs := `Post "https://payment.svc.cluster.local:8080/charge": read: connection reset by peer`

	res := AnalyzeNetTLSProxyLogs(logs)
	if res == nil {
		t.Fatalf("expected NetTLSProxyAnalysis, got nil")
	}
	if res.RootCause != "TCPConnectionReset" {
		t.Fatalf("expected TCPConnectionReset, got %s", res.RootCause)
	}
}

func TestAnalyzeNetTLSProxyLogs_EphemeralPort(t *testing.T) {
	logs := `dial tcp 10.244.2.15:5432: connect: cannot assign requested address`

	res := AnalyzeNetTLSProxyLogs(logs)
	if res == nil {
		t.Fatalf("expected NetTLSProxyAnalysis, got nil")
	}
	if res.RootCause != "EphemeralPortExhaustion" {
		t.Fatalf("expected EphemeralPortExhaustion, got %s", res.RootCause)
	}
}
