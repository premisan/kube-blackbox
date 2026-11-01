package knowledge

import (
	"testing"
)

func TestAnalyzeClusterInfraLogs_NFSAccessDenied(t *testing.T) {
	logs := `mount.nfs: access denied by server while mounting 192.168.1.100:/export/data`

	res := AnalyzeClusterInfraLogs(logs)
	if res == nil {
		t.Fatalf("expected ClusterInfraAnalysis, got nil")
	}
	if res.RootCause != "NFSMountAccessDenied" {
		t.Fatalf("expected NFSMountAccessDenied, got %s", res.RootCause)
	}
}

func TestAnalyzeClusterInfraLogs_MetricsScrape(t *testing.T) {
	logs := `E1102 02:00:00.123456       1 manager.go:111] unable to fully scrape metrics from node "worker-node-1": dial tcp 10.0.0.12:10250: i/o timeout`

	res := AnalyzeClusterInfraLogs(logs)
	if res == nil {
		t.Fatalf("expected ClusterInfraAnalysis, got nil")
	}
	if res.RootCause != "MetricsServerKubeletScrapeFailed" {
		t.Fatalf("expected MetricsServerKubeletScrapeFailed, got %s", res.RootCause)
	}
}

func TestAnalyzeClusterInfraLogs_LiteLLMRateLimit(t *testing.T) {
	logs := `litellm.exceptions.RateLimitError: RateLimitError: LLM Provider returned rate limit error: 429 Too Many Requests (TPM/RPM limit exceeded)`

	res := AnalyzeClusterInfraLogs(logs)
	if res == nil {
		t.Fatalf("expected ClusterInfraAnalysis, got nil")
	}
	if res.RootCause != "LiteLLMRateLimitExceeded" {
		t.Fatalf("expected LiteLLMRateLimitExceeded, got %s", res.RootCause)
	}
}
