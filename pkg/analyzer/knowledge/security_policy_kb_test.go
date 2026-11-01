package knowledge

import (
	"testing"
)

func TestAnalyzeSecurityPolicyLogs_KyvernoViolation(t *testing.T) {
	logs := `Error from server: error when creating "pod.yaml": admission webhook "validate.kyverno.svc" denied the request: response: [disallow-privileged-containers] Privileged container is not allowed`

	res := AnalyzeSecurityPolicyLogs(logs)
	if res == nil {
		t.Fatalf("expected SecurityPolicyAnalysis, got nil")
	}
	if res.RootCause != "KyvernoAdmissionPolicyViolation" {
		t.Fatalf("expected KyvernoAdmissionPolicyViolation, got %s", res.RootCause)
	}
}

func TestAnalyzeSecurityPolicyLogs_SecretsCSIMissing(t *testing.T) {
	logs := `Warning  FailedMount  10s  kubelet  MountVolume.SetUp failed for volume "secrets-store-inline" : secretproviderclasses.secrets-store.csi.x-k8s.io "app-vault-secret" not found`

	res := AnalyzeSecurityPolicyLogs(logs)
	if res == nil {
		t.Fatalf("expected SecurityPolicyAnalysis, got nil")
	}
	if res.RootCause != "SecretProviderClassNotFound" {
		t.Fatalf("expected SecretProviderClassNotFound, got %s", res.RootCause)
	}
}
