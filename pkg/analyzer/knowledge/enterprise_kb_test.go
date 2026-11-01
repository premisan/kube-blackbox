package knowledge

import (
	"testing"
)

func TestAnalyzeEnterpriseOSSLogs_VaultSealed(t *testing.T) {
	logs := `
2026-11-02T01:00:00.000Z [ERROR] core: vault is sealed
Error making API request.
URL: GET https://vault.vault.svc:8200/v1/secret/data/db
Code: 503. Errors:
* Vault is sealed
`
	res := AnalyzeEnterpriseOSSLogs(logs)
	if res == nil {
		t.Fatalf("expected non-nil EnterpriseOSSAnalysis")
	}
	if res.RootCause != "VaultSealedFailure" {
		t.Errorf("expected VaultSealedFailure, got %q", res.RootCause)
	}
	if res.Component != "vault" {
		t.Errorf("expected component vault, got %q", res.Component)
	}
}

func TestAnalyzeEnterpriseOSSLogs_CoreDNSLoop(t *testing.T) {
	logs := `
[INFO] plugin/reload: Running configuration SHA548
[FATAL] plugin/loop: Loop (127.0.0.1:53 -> :53) detected for zone ".", see https://coredns.io/plugins/loop#troubleshooting. Query: "HINFO 1234.4567."
`
	res := AnalyzeEnterpriseOSSLogs(logs)
	if res == nil {
		t.Fatalf("expected non-nil EnterpriseOSSAnalysis")
	}
	if res.RootCause != "CoreDNSLoopDetected" {
		t.Errorf("expected CoreDNSLoopDetected, got %q", res.RootCause)
	}
	if res.Component != "coredns" {
		t.Errorf("expected component coredns, got %q", res.Component)
	}
}

func TestAnalyzeEnterpriseOSSLogs_CertManagerWebhook(t *testing.T) {
	logs := `
Error from server (InternalError): Internal error occurred: failed calling webhook "webhook.cert-manager.io": failed to call webhook: Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": context deadline exceeded
`
	res := AnalyzeEnterpriseOSSLogs(logs)
	if res == nil {
		t.Fatalf("expected non-nil EnterpriseOSSAnalysis")
	}
	if res.RootCause != "CertManagerWebhookFailure" {
		t.Errorf("expected CertManagerWebhookFailure, got %q", res.RootCause)
	}
}

func TestAnalyzeEnterpriseOSSLogs_PrometheusWALCorruption(t *testing.T) {
	logs := `
ts=2026-11-02T01:00:00.000Z caller=main.go:800 level=error msg="opening storage failed: corrupted WAL segment /prometheus/data/wal/00000042: invalid record length"
`
	res := AnalyzeEnterpriseOSSLogs(logs)
	if res == nil {
		t.Fatalf("expected non-nil EnterpriseOSSAnalysis")
	}
	if res.RootCause != "PrometheusWALCorruption" {
		t.Errorf("expected PrometheusWALCorruption, got %q", res.RootCause)
	}
}

func TestAnalyzeEnterpriseOSSLogs_FluentBitBuffer(t *testing.T) {
	logs := `
[2026/11/02 01:00:00] [error] [buffer] ring buffer is full, cannot append chunk to elasticsearch.0
[2026/11/02 01:00:00] [warn] [engine] chunk '1-1730000000.42.flb' paused
`
	res := AnalyzeEnterpriseOSSLogs(logs)
	if res == nil {
		t.Fatalf("expected non-nil EnterpriseOSSAnalysis")
	}
	if res.RootCause != "FluentBitBufferExhaustion" {
		t.Errorf("expected FluentBitBufferExhaustion, got %q", res.RootCause)
	}
}

func TestAnalyzeEnterpriseOSSLogs_ElasticsearchFloodStage(t *testing.T) {
	logs := `
[2026-11-02T01:00:00,000][WARN ][o.e.c.r.a.DiskThresholdMonitor] [es-node-0] flood_stage disk watermark [95%] exceeded on [node-0][disk-data-0] free: 4.8gb[4.9%], all indices on this node will be marked read-only
`
	res := AnalyzeEnterpriseOSSLogs(logs)
	if res == nil {
		t.Fatalf("expected non-nil EnterpriseOSSAnalysis")
	}
	if res.RootCause != "ElasticsearchDiskFloodStage" {
		t.Errorf("expected ElasticsearchDiskFloodStage, got %q", res.RootCause)
	}
}

func TestAnalyzeEnterpriseOSSLogs_PatroniLease(t *testing.T) {
	logs := `
2026-11-02 01:00:00,000 INFO: demoting self because lost leader lease to etcd
2026-11-02 01:00:01,000 INFO: closed patroni connection
`
	res := AnalyzeEnterpriseOSSLogs(logs)
	if res == nil {
		t.Fatalf("expected non-nil EnterpriseOSSAnalysis")
	}
	if res.RootCause != "PatroniLeaderLeaseLost" {
		t.Errorf("expected PatroniLeaderLeaseLost, got %q", res.RootCause)
	}
}

func TestAnalyzeEnterpriseOSSLogs_ArgoRepoOOM(t *testing.T) {
	logs := `
time="2026-11-02T01:00:00Z" level=error msg="failed to generate manifests: ` + "`helm template .`" + ` failed exit status 137: signal: killed"
`
	res := AnalyzeEnterpriseOSSLogs(logs)
	if res == nil {
		t.Fatalf("expected non-nil EnterpriseOSSAnalysis")
	}
	if res.RootCause != "ArgoCDRepoServerOOM" {
		t.Errorf("expected ArgoCDRepoServerOOM, got %q", res.RootCause)
	}
}
