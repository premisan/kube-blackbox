package analyzer

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDiagnose_OOMKilled(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(137)
	input := DiagnosticInput{
		ContainerName: "app",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "app",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
					Reason:   "OOMKilled",
				},
			},
		},
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "OOMKilled" {
		t.Fatalf("expected RootCause OOMKilled, got %s", diag.RootCause)
	}
	if diag.Confidence != "High" {
		t.Fatalf("expected Confidence High, got %s", diag.Confidence)
	}
	if ev.ExitCode == nil || *ev.ExitCode != 137 {
		t.Fatalf("expected ExitCode 137, got %v", ev.ExitCode)
	}
}

func TestDiagnose_LivenessProbeFailed(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(137)
	now := metav1.Now()
	input := DiagnosticInput{
		ContainerName: "web",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "web",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode:   exitCode,
					Reason:     "Error",
					FinishedAt: now,
				},
			},
		},
		Events: []corev1.Event{
			{
				Type:          "Warning",
				Reason:        "Unhealthy",
				Message:       "Liveness probe failed: HTTP probe failed with statuscode: 500",
				LastTimestamp: now,
				Count:         3,
			},
		},
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "LivenessProbeFailure" {
		t.Fatalf("expected RootCause LivenessProbeFailure, got %s", diag.RootCause)
	}
	if diag.Confidence != "High" {
		t.Fatalf("expected Confidence High, got %s", diag.Confidence)
	}
	if len(ev.MatchedEvents) == 0 {
		t.Fatalf("expected matched events, got none")
	}
}

func TestDiagnose_AppPanicInLogs(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(2)
	now := metav1.Now()
	logs := `2026-10-31T10:00:00Z Starting server...
2026-10-31T10:00:05Z Handling request...
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x10a2f4]

goroutine 1 [running]:
main.main()
	/app/main.go:42 +0x1a`

	input := DiagnosticInput{
		ContainerName: "backend",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "backend",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode:   exitCode,
					Reason:     "Error",
					FinishedAt: now,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "AppPanic" {
		t.Fatalf("expected RootCause AppPanic, got %s", diag.RootCause)
	}
	if diag.Confidence != "High" {
		t.Fatalf("expected Confidence High, got %s", diag.Confidence)
	}
	if ev.MatchedLogPattern != "GoPanic" {
		t.Fatalf("expected pattern GoPanic, got %s", ev.MatchedLogPattern)
	}
}

func TestDiagnose_PortConflict(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)
	logs := `Error: listen tcp :8080: bind: address already in use`

	input := DiagnosticInput{
		ContainerName: "server",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "server",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode:   exitCode,
					Reason:     "Error",
					FinishedAt: metav1.Time{Time: time.Now()},
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, _ := engine.Diagnose(input)
	if diag.RootCause != "PortConflict" {
		t.Fatalf("expected RootCause PortConflict, got %s", diag.RootCause)
	}
}
