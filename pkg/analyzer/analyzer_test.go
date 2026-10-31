package analyzer

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
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
	if diag.Category != "Infrastructure" {
		t.Fatalf("expected Category Infrastructure, got %s", diag.Category)
	}
	if diag.Confidence != "High" {
		t.Fatalf("expected Confidence High, got %s", diag.Confidence)
	}
	if diag.RecommendedAction == "" {
		t.Fatalf("expected RecommendedAction, got empty")
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
	if diag.Category != "Infrastructure" {
		t.Fatalf("expected Category Infrastructure, got %s", diag.Category)
	}
	if len(ev.MatchedEvents) == 0 {
		t.Fatalf("expected matched events, got none")
	}
}

func TestDiagnose_ArchitectureMismatch(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)
	logs := `standard_init_linux.go:228: exec user process caused: exec format error`

	input := DiagnosticInput{
		ContainerName: "app",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "app",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "ArchitectureMismatch" {
		t.Fatalf("expected ArchitectureMismatch, got %s", diag.RootCause)
	}
	if diag.Category != "Configuration" {
		t.Fatalf("expected Category Configuration, got %s", diag.Category)
	}
	if ev.ErrorClass != "ExecFormatError" {
		t.Fatalf("expected ErrorClass ExecFormatError, got %s", ev.ErrorClass)
	}
}

func TestDiagnose_JVMHeapOOM(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)
	logs := `Exception in thread "main" java.lang.OutOfMemoryError: Java heap space
	at com.example.service.DataProcessor.loadAll(DataProcessor.java:85)
	at com.example.service.Application.main(Application.java:23)`

	input := DiagnosticInput{
		ContainerName: "api",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "api",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "JVMHeapOOM" {
		t.Fatalf("expected JVMHeapOOM, got %s", diag.RootCause)
	}
	if ev.ErrorClass != "OutOfMemoryError" {
		t.Fatalf("expected ErrorClass OutOfMemoryError, got %s", ev.ErrorClass)
	}
	if ev.ErrorLocation != "DataProcessor.java:85" {
		t.Fatalf("expected ErrorLocation DataProcessor.java:85, got %s", ev.ErrorLocation)
	}
}

func TestDiagnose_GoDeadlock(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(2)
	logs := `fatal error: all goroutines are asleep - deadlock!

goroutine 1 [semacquire]:
sync.runtime_SemacquireMutex(0xc000096014, 0x0, 0x0)
	/usr/local/go/src/runtime/sema.go:71 +0x25
sync.(*Mutex).lockSlow(0xc000096010)
	/usr/local/go/src/sync/mutex.go:138 +0x165
main.main()
	/app/worker.go:42 +0x65`

	input := DiagnosticInput{
		ContainerName: "worker",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "worker",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "GoDeadlock" {
		t.Fatalf("expected GoDeadlock, got %s", diag.RootCause)
	}
	if ev.ErrorLocation != "sema.go:71" {
		t.Fatalf("expected sema.go:71, got %s", ev.ErrorLocation)
	}
}

func TestDiagnose_NodeHeapOOM(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(134)
	logs := `<--- Last few GCs --->
[1:0x55dc98a] 45123 ms: Mark-sweep 2041.2 (2052.1) -> 2040.5 (2052.1) MB, 120.3 / 0.0 ms
<--- JS stacktrace --->
FATAL ERROR: Ineffective mark-compacts near heap limit Allocation failed - JavaScript heap out of memory`

	input := DiagnosticInput{
		ContainerName: "node-app",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "node-app",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "NodeHeapOOM" {
		t.Fatalf("expected NodeHeapOOM, got %s", diag.RootCause)
	}
	if ev.ErrorClass != "JavaScriptHeapOOM" {
		t.Fatalf("expected JavaScriptHeapOOM, got %s", ev.ErrorClass)
	}
}

func TestDiagnose_ProbableOOMWithMemoryLimit(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(137)
	logs := `OutOfMemory: unable to allocate 1048576 bytes`

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "worker",
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("128Mi"),
						},
					},
				},
			},
		},
	}

	input := DiagnosticInput{
		Pod:           pod,
		ContainerName: "worker",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "worker",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
					Reason:   "Error", // Not marked as OOMKilled by runtime bug
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "ProbableOOMKilled" {
		t.Fatalf("expected ProbableOOMKilled, got %s", diag.RootCause)
	}
	if diag.Confidence != "High" {
		t.Fatalf("expected Confidence High, got %s", diag.Confidence)
	}
	if ev.ErrorClass != "ProbableOOM" {
		t.Fatalf("expected ProbableOOM, got %s", ev.ErrorClass)
	}
}

func TestDiagnose_DatabaseAuthFailed(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)
	logs := `FATAL: password authentication failed for user "postgres"`

	input := DiagnosticInput{
		ContainerName: "backend",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "backend",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "DatabaseAuthFailure" {
		t.Fatalf("expected DatabaseAuthFailure, got %s", diag.RootCause)
	}
	if diag.Category != "Configuration" {
		t.Fatalf("expected Category Configuration, got %s", diag.Category)
	}
	if ev.ErrorClass != "AuthFailed" {
		t.Fatalf("expected AuthFailed, got %s", ev.ErrorClass)
	}
}

func TestDiagnose_PythonModuleNotFound(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)
	logs := `Traceback (most recent call last):
  File "app.py", line 3, in <module>
    import requests
ModuleNotFoundError: No module named 'requests'`

	input := DiagnosticInput{
		ContainerName: "crawler",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "crawler",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "PythonModuleNotFound" {
		t.Fatalf("expected PythonModuleNotFound, got %s", diag.RootCause)
	}
	if diag.Category != "Configuration" {
		t.Fatalf("expected Category Configuration, got %s", diag.Category)
	}
	if ev.ErrorClass != "ModuleNotFoundError" {
		t.Fatalf("expected ModuleNotFoundError, got %s", ev.ErrorClass)
	}
}

func TestDiagnose_RustPanic(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(101)
	logs := `thread 'main' panicked at 'called Option::unwrap() on a None value', src/main.rs:15:9
note: run with RUST_BACKTRACE=1 environment variable to display a backtrace`

	input := DiagnosticInput{
		ContainerName: "rust-service",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "rust-service",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "RustPanic" {
		t.Fatalf("expected RustPanic, got %s", diag.RootCause)
	}
	if ev.ErrorClass != "RustPanic" {
		t.Fatalf("expected RustPanic, got %s", ev.ErrorClass)
	}
}

func TestDiagnose_VolumeMountFailure(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)
	input := DiagnosticInput{
		ContainerName: "db",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "db",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		Events: []corev1.Event{
			{
				Type:    "Warning",
				Reason:  "FailedMount",
				Message: "MountVolume.SetUp failed for volume \"pvc-data\": rpc error: code = Internal desc = volume attachment timeout",
			},
		},
	}

	diag, _ := engine.Diagnose(input)
	if diag.RootCause != "VolumeMountFailure" {
		t.Fatalf("expected VolumeMountFailure, got %s", diag.RootCause)
	}
	if diag.Category != "Infrastructure" {
		t.Fatalf("expected Category Infrastructure, got %s", diag.Category)
	}
}
