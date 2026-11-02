package analyzer

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
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
	if diag.RootCause != "RustPanic" && diag.RootCause != "RustUnwrapNone" {
		t.Fatalf("expected RustPanic or RustUnwrapNone, got %s", diag.RootCause)
	}
	if ev.ErrorClass != "RustPanic" && ev.ErrorClass != "UnwrapNone" {
		t.Fatalf("expected RustPanic or UnwrapNone, got %s", ev.ErrorClass)
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

func TestDiagnose_DotNetNullReference(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)
	logs := `Unhandled exception. System.NullReferenceException: Object reference not set to an instance of an object.
   at OrderService.Controllers.OrdersController.Get(Int32 id) in /src/Controllers/OrdersController.cs:line 42
   at Microsoft.AspNetCore.Mvc.Infrastructure.ActionMethodExecutor.Execute`

	input := DiagnosticInput{
		ContainerName: "dotnet-api",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "dotnet-api",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "DotNetNullReference" {
		t.Fatalf("expected DotNetNullReference, got %s", diag.RootCause)
	}
	if ev.CulpritCode == nil {
		t.Fatalf("expected CulpritCode, got nil")
	}
	if ev.CulpritCode.File != "OrdersController.cs" || ev.CulpritCode.Line != 42 {
		t.Fatalf("expected OrdersController.cs:42, got %s:%d", ev.CulpritCode.File, ev.CulpritCode.Line)
	}
}

func TestDiagnose_JSONLogs_Unpacking(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(2)
	// Log emitted by uber-go/zap in JSON format
	logs := `{"level":"info","ts":1600000000,"msg":"Starting server"}
{"level":"fatal","ts":1600000001,"msg":"runtime error","stacktrace":"panic: runtime error: invalid memory address or nil pointer dereference\n\tmain.go:88"}`

	input := DiagnosticInput{
		ContainerName: "zap-worker",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "zap-worker",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "GoPanic" && diag.RootCause != "GoNilPointerDereference" {
		t.Fatalf("expected GoPanic or GoNilPointerDereference, got %s", diag.RootCause)
	}
	if ev.CulpritCode == nil || ev.CulpritCode.Line != 88 {
		t.Fatalf("expected CulpritCode line 88, got %v", ev.CulpritCode)
	}
}

func TestDiagnose_Multilingual_Korean(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(137)
	input := DiagnosticInput{
		ContainerName: "app",
		Language:      "ko",
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

	diag, _ := engine.Diagnose(input)
	if diag.RootCause != "OOMKilled" {
		t.Fatalf("expected RootCause OOMKilled, got %s", diag.RootCause)
	}
	// Verify Korean translation
	if !containsKorean(diag.Summary) {
		t.Fatalf("expected Korean summary, got: %s", diag.Summary)
	}
	if !containsKorean(diag.RecommendedAction) {
		t.Fatalf("expected Korean recommended action, got: %s", diag.RecommendedAction)
	}
}

func containsKorean(s string) bool {
	for _, r := range s {
		if r >= 0xAC00 && r <= 0xD7A3 {
			return true
		}
	}
	return false
}

func TestDiagnose_SidecarCascade(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)
	sidecarExitCode := int32(137)

	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name: "app",
					LastTerminationState: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode: exitCode,
						},
					},
				},
				{
					Name: "cloud-sql-proxy",
					LastTerminationState: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode: sidecarExitCode,
							Reason:   "OOMKilled",
						},
					},
				},
			},
		},
	}

	input := DiagnosticInput{
		Pod:             pod,
		ContainerName:   "app",
		ContainerStatus: &pod.Status.ContainerStatuses[0],
		PreviousLogs:    "dial tcp 127.0.0.1:5432: connect: connection refused",
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "SidecarCascadeFailure" {
		t.Fatalf("expected SidecarCascadeFailure, got %s", diag.RootCause)
	}
	if ev.SidecarCascade == "" {
		t.Fatalf("expected SidecarCascade description, got empty")
	}
}

func TestDiagnose_InitContainerFailed(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)
	initExitCode := int32(1)

	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{
				{
					Name: "flyway-migration",
					LastTerminationState: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode: initExitCode,
							Reason:   "Error",
						},
					},
				},
			},
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name: "web",
					LastTerminationState: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode: exitCode,
						},
					},
				},
			},
		},
	}

	input := DiagnosticInput{
		Pod:             pod,
		ContainerName:   "web",
		ContainerStatus: &pod.Status.ContainerStatuses[0],
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "InitContainerFailed" {
		t.Fatalf("expected InitContainerFailed, got %s", diag.RootCause)
	}
	if ev.ErrorClass != "InitContainerFailure" {
		t.Fatalf("expected InitContainerFailure, got %s", ev.ErrorClass)
	}
}

func TestDiagnose_SpringHikariPoolExhaustion(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)
	logs := `[WARN] 2026-11-02 00:00:01 HikariPool-1 - Connection is not available, request timed out after 30000ms.`

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
	if diag.RootCause != "SpringHikariPoolExhaustion" {
		t.Fatalf("expected SpringHikariPoolExhaustion, got %s", diag.RootCause)
	}
	if ev.ErrorClass != "ConnectionPoolExhausted" {
		t.Fatalf("expected ConnectionPoolExhausted, got %s", ev.ErrorClass)
	}
}

func TestDiagnose_KafkaBrokerUnavailable(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)
	logs := `org.apache.kafka.common.errors.TimeoutException: Failed to update metadata after 60000 ms.`

	input := DiagnosticInput{
		ContainerName: "consumer",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "consumer",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "KafkaBrokerUnavailable" {
		t.Fatalf("expected KafkaBrokerUnavailable, got %s", diag.RootCause)
	}
	if ev.ErrorClass != "KafkaUnavailable" {
		t.Fatalf("expected KafkaUnavailable, got %s", ev.ErrorClass)
	}
}

func TestDiagnose_FileDescriptorExhaustion(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)
	logs := `2026/11/02 00:00:01 accept: too many open files in system`

	input := DiagnosticInput{
		ContainerName: "gateway",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "gateway",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "FileDescriptorExhaustion" {
		t.Fatalf("expected FileDescriptorExhaustion, got %s", diag.RootCause)
	}
	if ev.ErrorClass != "EMFILE" {
		t.Fatalf("expected EMFILE, got %s", ev.ErrorClass)
	}
}

func TestDiagnose_BusError(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(135) // SIGBUS

	input := DiagnosticInput{
		ContainerName: "mmap-proc",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "mmap-proc",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "BusError" {
		t.Fatalf("expected BusError, got %s", diag.RootCause)
	}
	if ev.ErrorClass != "SIGBUS" {
		t.Fatalf("expected SIGBUS, got %s", ev.ErrorClass)
	}
}

func TestDiagnose_GlibcHeapCorruption(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(134)
	logs := `*** Error in '/app/server': double free or corruption (out): 0x0000000001f3b200 ***
./src/native_calc.cpp:45 in calculate()`

	input := DiagnosticInput{
		ContainerName: "native-worker",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "native-worker",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "HeapCorruption" {
		t.Fatalf("expected HeapCorruption, got %s", diag.RootCause)
	}
	if ev.ErrorClass != "GlibcHeapCorruption" {
		t.Fatalf("expected GlibcHeapCorruption, got %s", ev.ErrorClass)
	}
	if ev.CulpritCode == nil || ev.CulpritCode.File != "native_calc.cpp" || ev.CulpritCode.Line != 45 {
		t.Fatalf("expected culprit native_calc.cpp:45, got %+v", ev.CulpritCode)
	}
}

func TestDiagnose_ReadOnlyFilesystem(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)
	logs := `2026/11/02 00:00:01 open /tmp/cache.db: read-only file system`

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
	if diag.RootCause != "ReadOnlyFilesystemError" {
		t.Fatalf("expected ReadOnlyFilesystemError, got %s", diag.RootCause)
	}
	if ev.ErrorClass != "EROFS" {
		t.Fatalf("expected EROFS, got %s", ev.ErrorClass)
	}
}

func TestDiagnose_GracePeriodTimeout(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(137)
	grace := int64(30)
	now := time.Now()
	startTime := now.Add(-40 * time.Second)

	input := DiagnosticInput{
		ContainerName: "web",
		Pod: &corev1.Pod{
			Spec: corev1.PodSpec{
				TerminationGracePeriodSeconds: &grace,
				Containers: []corev1.Container{
					{Name: "web"},
				},
			},
		},
		ContainerStatus: &corev1.ContainerStatus{
			Name: "web",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode:   exitCode,
					StartedAt:  metav1.Time{Time: startTime},
					FinishedAt: metav1.Time{Time: now},
				},
			},
		},
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "GracefulShutdownTimeout" {
		t.Fatalf("expected GracefulShutdownTimeout, got %s", diag.RootCause)
	}
	if !ev.GracePeriodExceeded {
		t.Fatalf("expected GracePeriodExceeded to be true")
	}
	if ev.UptimeSeconds == nil || *ev.UptimeSeconds < 30 {
		t.Fatalf("expected UptimeSeconds >= 30, got %+v", ev.UptimeSeconds)
	}
}

func TestDiagnose_CPUThrottlingWithLiveness(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(137)
	now := time.Now()

	input := DiagnosticInput{
		ContainerName: "api",
		Pod: &corev1.Pod{
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "api",
						Resources: corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								corev1.ResourceCPU: resource.MustParse("100m"),
							},
						},
					},
				},
			},
		},
		ContainerStatus: &corev1.ContainerStatus{
			Name: "api",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode:   exitCode,
					FinishedAt: metav1.Time{Time: now},
				},
			},
		},
		Events: []corev1.Event{
			{
				Reason:        "Unhealthy",
				Message:       "Liveness probe failed: HTTP probe failed with statuscode: 500",
				LastTimestamp: metav1.Time{Time: now},
			},
		},
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "LivenessProbeFailure" {
		t.Fatalf("expected LivenessProbeFailure, got %s", diag.RootCause)
	}
	if !strings.Contains(diag.Summary, "CPU") && !strings.Contains(diag.Summary, "100m") {
		t.Fatalf("expected CPU throttling note in summary, got: %s", diag.Summary)
	}
	if ev.ResourceConstraints == "" || !strings.Contains(ev.ResourceConstraints, "CPULimit") {
		t.Fatalf("expected ResourceConstraints with CPULimit, got: %s", ev.ResourceConstraints)
	}
}

func TestDiagnose_PythonUnhandledException_ValueError(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)
	logs := `[INFO] Python worker service started successfully
[INFO] Processing batch analytics jobs...
[ERROR] Fatal error during batch processing:
Traceback (most recent call last):
  File "<string>", line 11, in <module>
  File "<string>", line 4, in process_record
ValueError: Corrupted payload detected for record_id=42`

	input := DiagnosticInput{
		ContainerName: "python-worker",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "python-worker",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "PythonUnhandledException" && diag.RootCause != "PythonValueError" {
		t.Fatalf("expected PythonUnhandledException or PythonValueError, got %s", diag.RootCause)
	}
	if ev.ErrorClass != "ValueError" {
		t.Fatalf("expected ErrorClass to be ValueError, got: %s", ev.ErrorClass)
	}
	if ev.CulpritCode == nil || ev.CulpritCode.Function != "process_record" {
		t.Fatalf("expected culprit function process_record, got: %+v", ev.CulpritCode)
	}
	if !strings.Contains(diag.Summary, "ValueError") {
		t.Fatalf("expected summary to mention ValueError, got: %s", diag.Summary)
	}
}

func TestDiagnose_PythonChainedException(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `
Traceback (most recent call last):
  File "/app/services/db.py", line 45, in connect_db
    raise ConnectionRefusedError("Failed to connect to postgres:5432")
ConnectionRefusedError: Failed to connect to postgres:5432

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/app/main.py", line 88, in startup_event
    connect_db()
  File "/app/services/db.py", line 48, in connect_db
    raise RuntimeError("Application bootstrap failed due to database connectivity")
RuntimeError: Application bootstrap failed due to database connectivity`

	input := DiagnosticInput{
		ContainerName: "fastapi-app",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "fastapi-app",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "PythonUnhandledException" && diag.RootCause != "PythonValueError" {
		t.Fatalf("expected PythonUnhandledException or PythonValueError, got %s", diag.RootCause)
	}
	if !strings.Contains(ev.ErrorClass, "ConnectionRefusedError") {
		t.Fatalf("expected ErrorClass to capture chained root cause, got: %s", ev.ErrorClass)
	}
	if ev.CulpritCode == nil || ev.CulpritCode.File != "db.py" {
		t.Fatalf("expected culprit db.py, got: %+v", ev.CulpritCode)
	}
}

func TestDiagnose_JavaSpringDeepCausedBy(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `
org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'userController': Injection of autowired dependencies failed
	at org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor.postProcessProperties(AutowiredAnnotationBeanPostProcessor.java:515)
Caused by: org.springframework.beans.factory.UnsatisfiedDependencyException: Error creating bean with name 'userService': Unsatisfied dependency expressed through field 'dataSource'
	at org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor$AutowiredFieldElement.resolveFieldValue(AutowiredAnnotationBeanPostProcessor.java:787)
Caused by: com.zaxxer.hikari.pool.HikariPool$PoolInitializationException: Failed to initialize pool: Connection refused
	at com.zaxxer.hikari.pool.HikariPool.checkFailFast(HikariPool.java:549)
Caused by: java.sql.SQLNonTransientConnectionException: Could not connect to address=(host=10.96.0.4)(port=3306): Connection refused
	at com.mysql.cj.jdbc.exceptions.SQLError.createSQLException(SQLError.java:110)
	at com.company.payment.repository.OrderRepository.findPending(OrderRepository.java:42)`

	input := DiagnosticInput{
		ContainerName: "spring-app",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "spring-app",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if ev.ErrorClass != "java.sql.SQLNonTransientConnectionException" {
		t.Fatalf("expected root unwrapped error class SQLNonTransientConnectionException, got: %s", ev.ErrorClass)
	}
	if ev.CulpritCode == nil || ev.CulpritCode.File != "OrderRepository.java" || ev.CulpritCode.Line != 42 {
		t.Fatalf("expected culprit OrderRepository.java:42, got: %+v", ev.CulpritCode)
	}
	if diag.Confidence != "High" {
		t.Fatalf("expected High confidence, got: %s", diag.Confidence)
	}
}

func TestDiagnose_NodePrismaDeepError(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `
PrismaClientKnownRequestError: 
Invalid 'prisma.user.create()' invocation:
Unique constraint failed on the constraint: 'users_email_key' (P2002)
    at RequestHandler.handleRequestError (/app/node_modules/@prisma/client/runtime/library.js:122:7147)
    at async createUser (/app/src/services/userService.ts:45:18)
    at async handleSignUp (/app/src/controllers/authController.ts:24:12)`

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
	if diag.RootCause != "NodePrismaError" {
		t.Fatalf("expected NodePrismaError, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "Prisma_P2002" {
		t.Fatalf("expected Prisma_P2002, got: %s", ev.ErrorClass)
	}
	if ev.CulpritCode == nil || ev.CulpritCode.File != "userService.ts" || ev.CulpritCode.Line != 45 {
		t.Fatalf("expected culprit userService.ts:45, got: %+v", ev.CulpritCode)
	}
}

func TestDiagnose_MeshEnvoyCircuitBreaker(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(0)

	logs := `[2026-11-02T02:00:00.123Z] "POST /api/v1/orders HTTP/1.1" 503 UO 0 0 1 - "-" "curl/8.0" "order-service.prod:8080" "10.244.1.25:8080" outbound|8080||order-service.prod.svc.cluster.local - 10.244.1.25:8080 10.244.0.12:45678 - default`

	input := DiagnosticInput{
		ContainerName: "istio-proxy",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "istio-proxy",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "EnvoyCircuitBreakerOverflow" {
		t.Fatalf("expected EnvoyCircuitBreakerOverflow, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "EnvoyFlag_UO" {
		t.Fatalf("expected EnvoyFlag_UO, got: %s", ev.ErrorClass)
	}
	if !strings.Contains(diag.RecommendedAction, "DestinationRule") {
		t.Fatalf("expected recommendation to mention DestinationRule, got: %s", diag.RecommendedAction)
	}
}

func TestDiagnose_MeshIstioStartupRace(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	now := metav1.Now()
	// app started at T, proxy started at T+2 and not ready
	appStartTime := metav1.NewTime(now.Add(-10 * time.Second))
	proxyStartTime := metav1.NewTime(now.Add(-8 * time.Second))

	input := DiagnosticInput{
		ContainerName: "main-app",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "main-app",
			State: corev1.ContainerState{
				Running: &corev1.ContainerStateRunning{
					StartedAt: appStartTime,
				},
			},
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: "dial tcp 10.96.0.1:443: connect: connection refused\nfatal error connecting to external database",
		Pod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "order-pod",
				Namespace: "default",
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name:  "main-app",
						Ready: false,
						State: corev1.ContainerState{
							Running: &corev1.ContainerStateRunning{StartedAt: appStartTime},
						},
					},
					{
						Name:  "istio-proxy",
						Ready: false,
						State: corev1.ContainerState{
							Running: &corev1.ContainerStateRunning{StartedAt: proxyStartTime},
						},
					},
				},
			},
		},
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "IstioStartupRaceCondition" {
		t.Fatalf("expected IstioStartupRaceCondition, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "StartupRaceCondition" {
		t.Fatalf("expected StartupRaceCondition, got: %s", ev.ErrorClass)
	}
}

func TestDiagnose_EnterpriseVaultSealed(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `[INFO] vault-agent: starting auto-auth
[ERROR] vault-agent: failed to read secret "secret/data/db": Error making API request.
URL: GET https://vault.vault.svc:8200/v1/secret/data/db
Code: 503. Errors:
* Vault is sealed`

	input := DiagnosticInput{
		ContainerName: "vault-agent",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "vault-agent",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "VaultSealedFailure" {
		t.Fatalf("expected VaultSealedFailure, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "VaultSealed_503" {
		t.Fatalf("expected VaultSealed_503, got: %s", ev.ErrorClass)
	}
	if !strings.Contains(diag.RecommendedAction, "vault operator unseal") {
		t.Fatalf("expected action to mention unseal, got: %s", diag.RecommendedAction)
	}
}

func TestDiagnose_EnterpriseCoreDNSLoop(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(2)

	logs := `[INFO] plugin/reload: Running configuration MD5 = 20e7e1f4f89d
plugin/loop: Loop (127.0.0.1:53 -> :53) detected for zone ".", see https://coredns.io/plugins/loop#troubleshooting.
CoreDNS is halting to avoid a loop.`

	input := DiagnosticInput{
		ContainerName: "coredns",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "coredns",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "CoreDNSLoopDetected" {
		t.Fatalf("expected CoreDNSLoopDetected, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "DNSLoopDetected" {
		t.Fatalf("expected DNSLoopDetected, got: %s", ev.ErrorClass)
	}
}

func TestDiagnose_GCPGeminiQuota(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `google.genai.errors.APIError: 429 RESOURCE_EXHAUSTED. Quota exceeded for Generate Content API requests`
	input := DiagnosticInput{
		ContainerName: "ai-service",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "ai-service",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "GCPGeminiQuotaExceeded" {
		t.Fatalf("expected GCPGeminiQuotaExceeded, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "Gemini_ResourceExhausted_429" {
		t.Fatalf("expected Gemini_ResourceExhausted_429, got: %s", ev.ErrorClass)
	}
}

func TestDiagnose_ClickHouseParts(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `DB::Exception: Too many parts (320) in all data parts in table. Merges are processing significantly slower than inserts.`
	input := DiagnosticInput{
		ContainerName: "clickhouse",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "clickhouse",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "ClickHouseTooManyParts" {
		t.Fatalf("expected ClickHouseTooManyParts, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "ClickHouse_TooManyParts" {
		t.Fatalf("expected ClickHouse_TooManyParts, got: %s", ev.ErrorClass)
	}
}

func TestDiagnose_KyvernoViolation(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `Error from server: admission webhook "validate.kyverno.svc" denied the request: policy require-run-as-non-root failed on resource`
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
	if diag.RootCause != "KyvernoAdmissionPolicyViolation" {
		t.Fatalf("expected KyvernoAdmissionPolicyViolation, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "Kyverno_PolicyViolation_Denied" {
		t.Fatalf("expected Kyverno_PolicyViolation_Denied, got: %s", ev.ErrorClass)
	}
}

func TestDiagnose_LiteLLMRateLimit(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `litellm.exceptions.RateLimitError: RateLimitError: LLM Provider returned rate limit error: 429 Too Many Requests (TPM/RPM limit exceeded)`
	input := DiagnosticInput{
		ContainerName: "litellm-proxy",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "litellm-proxy",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "LiteLLMRateLimitExceeded" {
		t.Fatalf("expected LiteLLMRateLimitExceeded, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "LiteLLM_Upstream_RateLimit" {
		t.Fatalf("expected LiteLLM_Upstream_RateLimit, got: %s", ev.ErrorClass)
	}
}

func TestDiagnose_SquidAuthRequired(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Basic realm="Squid proxy"
Connection: close`
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
	if diag.RootCause != "ProxyAuthenticationRequired" {
		t.Fatalf("expected ProxyAuthenticationRequired, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "Squid_407_AuthRequired" {
		t.Fatalf("expected Squid_407_AuthRequired, got: %s", ev.ErrorClass)
	}
}

func TestDiagnose_TLSUntrustedCA(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `javax.net.ssl.SSLHandshakeException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target`
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
	if diag.RootCause != "TLSUntrustedCA" {
		t.Fatalf("expected TLSUntrustedCA, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "TLS_Certificate_UnknownCA" {
		t.Fatalf("expected TLS_Certificate_UnknownCA, got: %s", ev.ErrorClass)
	}
}

func TestDiagnose_TCPConnectionReset(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `Post "https://api.internal.org/v1": read: connection reset by peer`
	input := DiagnosticInput{
		ContainerName: "gateway",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "gateway",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "TCPConnectionReset" {
		t.Fatalf("expected TCPConnectionReset, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "Network_TCP_ConnectionReset" {
		t.Fatalf("expected Network_TCP_ConnectionReset, got: %s", ev.ErrorClass)
	}
}





func TestDiagnose_DBDriver_MySQLDeadlock(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `
com.mysql.cj.jdbc.exceptions.MySQLTransactionRollbackException: Deadlock found when trying to get lock; try restarting transaction
	at com.mysql.cj.jdbc.exceptions.SQLError.createSQLException(SQLError.java:121)
	at com.mysql.cj.jdbc.exceptions.SQLError.createMySQLTransactionRollbackException(SQLError.java:112)
`
	input := DiagnosticInput{
		ContainerName: "payment-api",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "payment-api",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "MySQLDeadlock" {
		t.Fatalf("expected MySQLDeadlock, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "MySQL_1213_Deadlock" {
		t.Fatalf("expected MySQL_1213_Deadlock, got: %s", ev.ErrorClass)
	}
}

func TestDiagnose_DBDriver_PostgresInFailedTx(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `
Traceback (most recent call last):
  File "server.py", line 45, in execute_query
    cursor.execute("SELECT 1")
psycopg2.errors.InFailedSqlTransaction: current transaction is aborted, commands ignored until end of transaction block
`
	input := DiagnosticInput{
		ContainerName: "django-web",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "django-web",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "PostgresInFailedSQLTransaction" {
		t.Fatalf("expected PostgresInFailedSQLTransaction, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "PostgreSQL_25P02_InFailedTx" {
		t.Fatalf("expected PostgreSQL_25P02_InFailedTx, got: %s", ev.ErrorClass)
	}
}

func TestDiagnose_DBDriver_BigQueryPartitionFilter(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `
Traceback (most recent call last):
  File "export.py", line 19, in run
    query_job.result()
google.cloud.exceptions.BadRequest: 400 Cannot query over table 'corp-data.sales.orders' without a filter over column(s) 'order_date' that can be used for partition elimination
`
	input := DiagnosticInput{
		ContainerName: "bq-exporter",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "bq-exporter",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "BigQueryPartitionFilterRequired" {
		t.Fatalf("expected BigQueryPartitionFilterRequired, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "BigQuery_PartitionFilterRequired" {
		t.Fatalf("expected BigQuery_PartitionFilterRequired, got: %s", ev.ErrorClass)
	}
}

func TestDiagnoseWithPriorHistories_RecurrentFailure(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(137)
	now := time.Now()
	twoMinutesAgo := metav1.NewTime(now.Add(-2 * time.Minute))
	fourMinutesAgo := metav1.NewTime(now.Add(-4 * time.Minute))

	priors := []observerv1alpha1.PodRestartHistory{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test-pod-app-restart-2",
				CreationTimestamp: twoMinutesAgo,
			},
			Spec: observerv1alpha1.PodRestartHistorySpec{
				RestartCount: 2,
			},
			Status: observerv1alpha1.PodRestartHistoryStatus{
				Diagnosis: observerv1alpha1.Diagnosis{
					RootCause:  "OOMKilled",
					Category:   "Infrastructure",
					Confidence: "Medium",
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test-pod-app-restart-1",
				CreationTimestamp: fourMinutesAgo,
			},
			Spec: observerv1alpha1.PodRestartHistorySpec{
				RestartCount: 1,
			},
			Status: observerv1alpha1.PodRestartHistoryStatus{
				Diagnosis: observerv1alpha1.Diagnosis{
					RootCause:  "OOMKilled",
					Category:   "Infrastructure",
					Confidence: "Medium",
				},
			},
		},
	}

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
		PriorHistories: priors,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "OOMKilled" {
		t.Fatalf("expected RootCause OOMKilled, got %s", diag.RootCause)
	}
	if !ev.RecurrentFailure {
		t.Fatalf("expected RecurrentFailure true, got false")
	}
	if ev.ConsecutiveFailures != 3 {
		t.Fatalf("expected ConsecutiveFailures 3, got %d", ev.ConsecutiveFailures)
	}
	if diag.Confidence != "High" {
		t.Fatalf("expected Confidence promoted to High, got %s", diag.Confidence)
	}
	if len(ev.PriorRootCauses) != 2 || ev.PriorRootCauses[0] != "OOMKilled" {
		t.Fatalf("unexpected PriorRootCauses: %v", ev.PriorRootCauses)
	}
	if ev.TimeSinceLastRestartSeconds == nil || *ev.TimeSinceLastRestartSeconds <= 0 {
		t.Fatalf("expected positive TimeSinceLastRestartSeconds, got %v", ev.TimeSinceLastRestartSeconds)
	}
}

func TestDiagnoseWithPriorHistories_FailureTransition(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(137)
	now := time.Now()
	oneMinAgo := metav1.NewTime(now.Add(-1 * time.Minute))

	priors := []observerv1alpha1.PodRestartHistory{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test-pod-app-restart-1",
				CreationTimestamp: oneMinAgo,
			},
			Spec: observerv1alpha1.PodRestartHistorySpec{
				RestartCount: 1,
			},
			Status: observerv1alpha1.PodRestartHistoryStatus{
				Diagnosis: observerv1alpha1.Diagnosis{
					RootCause:  "DatabaseConnectionExhaustion",
					Category:   "Application",
					Confidence: "High",
				},
			},
		},
	}

	events := []corev1.Event{
		{
			Reason:  "Unhealthy",
			Message: "Liveness probe failed: HTTP probe failed with statuscode: 500",
		},
	}

	input := DiagnosticInput{
		ContainerName: "app",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "app",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
					Reason:   "Error",
				},
			},
		},
		Events:         events,
		PriorHistories: priors,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "LivenessProbeFailure" {
		t.Fatalf("expected RootCause LivenessProbeFailure, got %s", diag.RootCause)
	}
	expectedTransition := "DatabaseConnectionExhaustion -> LivenessProbeFailure"
	if ev.FailureTransition != expectedTransition {
		t.Fatalf("expected FailureTransition %s, got %s", expectedTransition, ev.FailureTransition)
	}
	if ev.RecurrentFailure {
		t.Fatalf("expected RecurrentFailure false for transitioned failure, got true")
	}
}

func TestDiagnose_PHPDeepCrash(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(255)

	logs := `
[02-Nov-2026 03:00:15 UTC] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in /var/www/html/app/Services/ReportGenerator.php on line 245
`
	input := DiagnosticInput{
		ContainerName: "php-api",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "php-api",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "PHPMemoryLimitExceeded" {
		t.Fatalf("expected PHPMemoryLimitExceeded, got: %s", diag.RootCause)
	}
	if ev.ErrorClass != "PHPMemoryLimitExceeded" {
		t.Fatalf("expected PHPMemoryLimitExceeded, got: %s", ev.ErrorClass)
	}
	if ev.CulpritCode == nil || ev.CulpritCode.File != "/var/www/html/app/Services/ReportGenerator.php" || ev.CulpritCode.Line != 245 {
		t.Fatalf("expected culprit code /var/www/html/app/Services/ReportGenerator.php:245, got: %+v", ev.CulpritCode)
	}
}

func TestDiagnose_ClickHouseGracePeriodNotNode(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(137)
	graceSec := int64(30)
	startedAt := metav1.NewTime(time.Now().Add(-69 * time.Second))
	finishedAt := metav1.Now()

	logs := `
16. ? @ 0x00007acd2f5d81c4
17. ? @ 0x00007acd2f657ac0
 (version 25.2.1.3085 (official build))
2026.10.29 17:10:33.131931 [ 43 ] {} <Information> Application: Closed all listening sockets.
2026.10.29 17:10:33.132186 [ 43 ] {} <Information> Application: Closed connections.
2026.10.29 17:10:33.132861 [ 43 ] {} <Information> Application: Stopping AsyncLoader.
2026.10.29 17:10:33.133135 [ 43 ] {} <Information> CgroupsMemoryUsageObserver: Stopped cgroup current memory usage observer thread
2026.10.29 17:10:33.144490 [ 43 ] {} <Information> Application: Shutting down storages.
2026.10.29 17:10:33.298563 [ 214 ] {} <Information> system.latency_log (027618c1-67e1-4506-86e3-f7305b726925) (MergerMutator): Selected 2 parts from 202610_2646230_2650088_3086 to 202610_2650089_2650089_0. Merge selecting phase took: 0ms
2026.10.29 17:10:33.354306 [ 211 ] {} <Error> system.text_log: Error occurred at merger mutator
`
	input := DiagnosticInput{
		ContainerName: "clickhouse",
		Pod: &corev1.Pod{
			Spec: corev1.PodSpec{
				TerminationGracePeriodSeconds: &graceSec,
			},
		},
		ContainerStatus: &corev1.ContainerStatus{
			Name: "clickhouse",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode:   exitCode,
					Reason:     "Error",
					StartedAt:  startedAt,
					FinishedAt: finishedAt,
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause == "NodeTypeError" || ev.MatchedLogPattern == "NodeDeepCrash" {
		t.Fatalf("ClickHouse container should NOT be diagnosed as NodeTypeError or NodeDeepCrash! Got RootCause: %s, MatchedPattern: %s", diag.RootCause, ev.MatchedLogPattern)
	}
	if diag.RootCause != "GracefulShutdownTimeout" {
		t.Fatalf("expected GracefulShutdownTimeout, got: %s", diag.RootCause)
	}
}

func TestDiagnose_FlaskGunicornShutdownNotNode(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(0)

	logs := `
connected to AWS IoT
[2026-10-30 02:28:36 +0900] [9] [INFO] Worker exiting (pid: 9)
connecting to IoT FLASK_ENV production AWS a2xjzp4d3ro6zs-ats.iot.ap-northeast-2.amazonaws.com
connect iot aws
connected to AWS IoT
[2026-10-30 02:28:36 +0900] [8] [INFO] Worker exiting (pid: 8)
connecting to IoT FLASK_ENV production AWS a2xjzp4d3ro6zs-ats.iot.ap-northeast-2.amazonaws.com
connect iot aws
connected to AWS IoT
[2026-10-30 02:28:37 +0900] [7] [INFO] Worker exiting (pid: 7)
connecting to IoT FLASK_ENV production AWS a2xjzp4d3ro6zs-ats.iot.ap-northeast-2.amazonaws.com
connect iot aws
connected to AWS IoT
[2026-10-30 02:28:46 +0900] [1] [INFO] Shutting down: Master
Error occurred at shutdown: None
`
	input := DiagnosticInput{
		ContainerName: "webserver",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "webserver",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
					Reason:   "Completed",
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause == "NodeTypeError" || ev.MatchedLogPattern == "NodeDeepCrash" {
		t.Fatalf("Python/Flask webserver should NOT be diagnosed as NodeTypeError or NodeDeepCrash! Got RootCause: %s, MatchedPattern: %s", diag.RootCause, ev.MatchedLogPattern)
	}
	if diag.RootCause != "ProcessExitedNormally" {
		t.Fatalf("expected ProcessExitedNormally, got: %s", diag.RootCause)
	}
}

func TestDiagnose_SentryGrade_PythonKeyErrorInApp(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `
[2026-11-02 12:00:00] [INFO] Handling batch order request
[2026-11-02 12:00:01] [INFO] User session authenticated (user_id: 1042)
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/site-packages/flask/app.py", line 1478, in __call__
    return self.wsgi_app(environ, start_response)
  File "/app/services/order_service.py", line 84, in process_order
    account_id = payload['account_id']
KeyError: 'account_id'
[2026-11-02 12:00:02] [INFO] Worker exiting (pid: 14)
`
	input := DiagnosticInput{
		ContainerName: "order-api",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "order-api",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
					Reason:   "Error",
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "PythonKeyError" && diag.RootCause != "PythonKeyOrIndexError" {
		t.Fatalf("expected PythonKeyError or PythonKeyOrIndexError, got: %s (should not fallback to ApplicationRuntimeError)", diag.RootCause)
	}
	if ev.ErrorLocation != "order_service.py:84" {
		t.Fatalf("expected order_service.py:84, got: %s", ev.ErrorLocation)
	}
	if ev.CulpritCode == nil || ev.CulpritCode.File != "order_service.py" || ev.CulpritCode.Line != 84 {
		t.Fatalf("expected In-App culprit order_service.py:84, got: %+v", ev.CulpritCode)
	}
}

func TestDiagnose_SentryGrade_JavaNPECausedByInApp(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `
2026-11-02 12:00:00.123 [main] INFO  com.example.Application - Started Application in 2.345 seconds
org.springframework.web.util.NestedServletException: Request processing failed; nested exception is java.lang.NullPointerException: Cannot invoke "String.length()" because "name" is null
	at org.springframework.web.servlet.FrameworkServlet.processRequest(FrameworkServlet.java:1014)
	at org.springframework.web.servlet.FrameworkServlet.doPost(FrameworkServlet.java:909)
Caused by: java.lang.NullPointerException: Cannot invoke "String.length()" because "name" is null
	at com.example.service.UserService.validateUser(UserService.java:125)
	at com.example.controller.UserController.createUser(UserController.java:45)
	at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
`
	input := DiagnosticInput{
		ContainerName: "user-service",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "user-service",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
					Reason:   "Error",
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "JavaNullPointerException" && diag.RootCause != "JVMNullPointer" {
		t.Fatalf("expected JavaNullPointerException or JVMNullPointer, got: %s", diag.RootCause)
	}
	if ev.ErrorLocation != "UserService.java:125" {
		t.Fatalf("expected UserService.java:125, got: %s", ev.ErrorLocation)
	}
	if ev.CulpritCode == nil || ev.CulpritCode.File != "UserService.java" || ev.CulpritCode.Line != 125 {
		t.Fatalf("expected In-App culprit UserService.java:125, got: %+v", ev.CulpritCode)
	}
}

func TestDiagnose_SentryGrade_GoPanicInApp(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(2)

	logs := `
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x89ab12]

goroutine 1 [running]:
main.processPayment(0x0)
	/app/payment/processor.go:55 +0x3a
main.main()
	/app/main.go:20 +0x125
`
	input := DiagnosticInput{
		ContainerName: "payment-service",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "payment-service",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
					Reason:   "Error",
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "GoNilPointerPanic" && diag.RootCause != "GoNilPointerDereference" {
		t.Fatalf("expected GoNilPointerPanic or GoNilPointerDereference, got: %s", diag.RootCause)
	}
	if ev.CulpritCode == nil || ev.CulpritCode.File != "processor.go" || ev.CulpritCode.Line != 55 {
		t.Fatalf("expected In-App culprit processor.go:55, got: %+v", ev.CulpritCode)
	}
}

func TestDiagnose_SentryGrade_PythonUnboundLocalErrorCustom(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `
[2026-11-02 12:00:00] [INFO] Starting invoice calculation batch
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/site-packages/django/core/handlers/base.py", line 181, in _get_response
    response = wrapped_callback(request, *callback_args, **callback_kwargs)
  File "/app/billing/calculator.py", line 142, in calculate_fee
    print(fee)
    fee = amount * 0.1
UnboundLocalError: local variable 'fee' referenced before assignment
[2026-11-02 12:00:02] [INFO] Worker exiting
`
	input := DiagnosticInput{
		ContainerName: "billing-api",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "billing-api",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
					Reason:   "Error",
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "PythonUnboundLocalError" {
		t.Fatalf("expected PythonUnboundLocalError, got: %s (should be resolved by Universal Semantic Catalog)", diag.RootCause)
	}
	if ev.ErrorLocation != "calculator.py:142" {
		t.Fatalf("expected calculator.py:142, got: %s", ev.ErrorLocation)
	}
	if ev.CulpritCode == nil || ev.CulpritCode.File != "calculator.py" || ev.CulpritCode.Line != 142 {
		t.Fatalf("expected calculator.py:142, got: %+v", ev.CulpritCode)
	}
	if !strings.Contains(diag.Summary, "UnboundLocalError") || !strings.Contains(diag.Summary, "calculator.py:142") {
		t.Fatalf("expected detailed Korean summary, got: %s", diag.Summary)
	}
	if !strings.Contains(diag.RecommendedAction, "초기화") {
		t.Fatalf("expected actionable recommendation, got: %s", diag.RecommendedAction)
	}
}

func TestDiagnose_SentryGrade_NodeReferenceErrorInApp(t *testing.T) {
	engine := NewDiagnosticEngine()
	exitCode := int32(1)

	logs := `
ReferenceError: configService is not defined
    at AuthService.login (/app/src/auth/auth.service.ts:48:15)
    at AuthController.login (/app/src/auth/auth.controller.ts:22:33)
    at /app/node_modules/@nestjs/core/router/router-execution-context.js:46:28
`
	input := DiagnosticInput{
		ContainerName: "auth-api",
		ContainerStatus: &corev1.ContainerStatus{
			Name: "auth-api",
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode,
					Reason:   "Error",
				},
			},
		},
		PreviousLogs: logs,
	}

	diag, ev := engine.Diagnose(input)
	if diag.RootCause != "NodeReferenceError" {
		t.Fatalf("expected NodeReferenceError, got: %s", diag.RootCause)
	}
	if ev.CulpritCode == nil || ev.CulpritCode.File != "auth.service.ts" || ev.CulpritCode.Line != 48 {
		t.Fatalf("expected In-App culprit auth.service.ts:48, got: %+v", ev.CulpritCode)
	}
}
