package knowledge

import (
	"testing"
)

func TestAnalyzeCICDGitOpsLogs_JenkinsDisk(t *testing.T) {
	logs := `WARNING: Disk space is below threshold of 1.000 GiB for node master. Free space: 512.000 MiB.
java.io.IOException: No space left on device
    at java.io.FileOutputStream.writeBytes(Native Method)`

	res := AnalyzeCICDGitOpsLogs(logs)
	if res == nil {
		t.Fatalf("expected CICDGitOpsAnalysis, got nil")
	}
	if res.RootCause != "JenkinsDiskSpaceExhausted" {
		t.Fatalf("expected JenkinsDiskSpaceExhausted, got %s", res.RootCause)
	}
}

func TestAnalyzeCICDGitOpsLogs_ArgoRolloutAnalysis(t *testing.T) {
	logs := `time="2026-11-02T02:00:00Z" level=error msg="AnalysisRun failed: Metric \"success-rate\" failed evaluation (value: 0.91, threshold: >=0.99)" rollout=frontend-rollout`

	res := AnalyzeCICDGitOpsLogs(logs)
	if res == nil {
		t.Fatalf("expected CICDGitOpsAnalysis, got nil")
	}
	if res.RootCause != "ArgoRolloutAnalysisFailed" {
		t.Fatalf("expected ArgoRolloutAnalysisFailed, got %s", res.RootCause)
	}
}
