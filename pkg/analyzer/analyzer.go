package analyzer

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	observerv1alpha1 "github.com/premisan/kube-pinger/api/v1alpha1"
)

type DiagnosticEngine struct{}

func NewDiagnosticEngine() *DiagnosticEngine {
	return &DiagnosticEngine{}
}

type DiagnosticInput struct {
	Pod             *corev1.Pod
	ContainerName   string
	ContainerStatus *corev1.ContainerStatus
	Events          []corev1.Event
	PreviousLogs    string
}

// Diagnose evaluates container termination status, events, logs, and pod specs to deduce root cause.
func (e *DiagnosticEngine) Diagnose(input DiagnosticInput) (observerv1alpha1.Diagnosis, observerv1alpha1.Evidence) {
	var evidence observerv1alpha1.Evidence
	var diagnosis observerv1alpha1.Diagnosis

	cs := input.ContainerStatus
	if cs == nil {
		diagnosis.Category = "Unknown"
		diagnosis.RootCause = "Unknown"
		diagnosis.Confidence = "Low"
		diagnosis.Summary = "No container status available"
		return diagnosis, evidence
	}

	var termState *corev1.ContainerStateTerminated
	if cs.LastTerminationState.Terminated != nil {
		termState = cs.LastTerminationState.Terminated
	} else if cs.State.Terminated != nil {
		termState = cs.State.Terminated
	}

	if termState != nil {
		code := termState.ExitCode
		evidence.ExitCode = &code
		evidence.TerminationReason = termState.Reason
	}

	var restartedAt time.Time
	if termState != nil && !termState.FinishedAt.IsZero() {
		restartedAt = termState.FinishedAt.Time
	}

	// 1. Analyze Events
	eventRes := AnalyzeEvents(input.Events, input.ContainerName, restartedAt)
	if eventRes != nil {
		evidence.MatchedEvents = eventRes.MatchedEvents
	}

	// 2. Analyze Logs
	logRes := AnalyzeLogs(input.PreviousLogs)
	if logRes != nil {
		evidence.LastLogSnippet = logRes.Snippet
		evidence.MatchedLogPattern = logRes.MatchedPattern
		evidence.ErrorClass = logRes.ErrorClass
		evidence.ErrorLocation = logRes.ErrorLocation
	}

	// ==================== Step 1: Explicit Kernel & Runtime Termination ====================
	if termState != nil {
		// OOMKilled by cgroup/kernel
		if termState.Reason == "OOMKilled" || (termState.ExitCode == 137 && termState.Reason == "OOMKilled") {
			diagnosis.Category = "Infrastructure"
			diagnosis.RootCause = "OOMKilled"
			diagnosis.Confidence = "High"
			diagnosis.Summary = "Container exceeded memory limit and was killed by Linux kernel OOM killer (cgroup memory exhaustion)."
			diagnosis.RecommendedAction = "Increase memory limit in pod spec (resources.limits.memory) or analyze memory leaks."
			evidence.ErrorClass = "LinuxOOMKiller"
			return diagnosis, evidence
		}

		// Exit code 126: Permission denied
		if termState.ExitCode == 126 {
			diagnosis.Category = "Configuration"
			diagnosis.RootCause = "PermissionDenied"
			diagnosis.Confidence = "High"
			diagnosis.Summary = "Container entrypoint binary lacks execute permission (Exit code 126)."
			diagnosis.RecommendedAction = "Add execution permissions (chmod +x) to entrypoint binary/script in Dockerfile."
			evidence.ErrorClass = "ExecPermissionDenied"
			return diagnosis, evidence
		}

		// Exit code 127: Command not found
		if termState.ExitCode == 127 {
			diagnosis.Category = "Configuration"
			diagnosis.RootCause = "CommandNotFound"
			diagnosis.Confidence = "High"
			diagnosis.Summary = "Container entrypoint executable or command was not found in image PATH (Exit code 127)."
			diagnosis.RecommendedAction = "Verify entrypoint path in Dockerfile and ensure required shell/binaries exist in base image."
			evidence.ErrorClass = "BinaryNotFound"
			return diagnosis, evidence
		}
	}

	// ==================== Step 2: Kubernetes Events Correlation ====================
	if eventRes != nil && eventRes.MatchedRule != nil {
		diagnosis.Category = eventRes.Category
		diagnosis.RootCause = eventRes.MatchedRule.RootCause
		diagnosis.Confidence = eventRes.MatchedRule.Confidence
		diagnosis.Summary = eventRes.Summary
		diagnosis.RecommendedAction = eventRes.RecommendedAction
		return diagnosis, evidence
	}

	// ==================== Step 3: Deep Log Signature Pattern Matching ====================
	if logRes != nil && logRes.MatchedRule != nil {
		diagnosis.Category = logRes.Category
		diagnosis.RootCause = logRes.MatchedRule.RootCause
		diagnosis.Confidence = logRes.MatchedRule.Confidence
		diagnosis.Summary = logRes.Summary
		diagnosis.RecommendedAction = logRes.RecommendedAction
		return diagnosis, evidence
	}

	// ==================== Step 4: Combined Heuristic Reasoning ====================
	if termState != nil {
		switch termState.ExitCode {
		case 137: // SIGKILL (128 + 9)
			// Check if container has memory limits defined and logs contain memory error
			if hasMemoryLimit(input.Pod, input.ContainerName) && containsMemoryKeywords(input.PreviousLogs) {
				diagnosis.Category = "Infrastructure"
				diagnosis.RootCause = "ProbableOOMKilled"
				diagnosis.Confidence = "High"
				diagnosis.Summary = "Container killed with SIGKILL (137) with memory limit defined and memory exhaustion indicators in log."
				diagnosis.RecommendedAction = "Increase pod memory limit (resources.limits.memory) or optimize memory consumption."
				evidence.ErrorClass = "ProbableOOM"
				return diagnosis, evidence
			}

			diagnosis.Category = "Infrastructure"
			diagnosis.RootCause = "SigkillTerminated"
			diagnosis.Confidence = "Medium"
			diagnosis.Summary = "Process killed by SIGKILL (Exit code 137). Typically unrecorded OOM, probe timeout, or forced eviction."
			diagnosis.RecommendedAction = "Inspect node dmesg logs for OOM killer events or check if liveness probes timed out."
			return diagnosis, evidence

		case 143: // SIGTERM (128 + 15)
			diagnosis.Category = "Infrastructure"
			diagnosis.RootCause = "SigtermShutdown"
			diagnosis.Confidence = "Medium"
			diagnosis.Summary = "Process received SIGTERM (Exit code 143) and terminated gracefully during deployment rollout, scaling, or node drain."
			diagnosis.RecommendedAction = "Normal during pod recreation. If unexpected, check deployment revision history or node maintenance."
			return diagnosis, evidence

		case 139: // SIGSEGV (128 + 11)
			diagnosis.Category = "Application"
			diagnosis.RootCause = "SegmentationFault"
			diagnosis.Confidence = "High"
			diagnosis.Summary = "Process crashed due to segmentation fault (SIGSEGV, Exit code 139)."
			diagnosis.RecommendedAction = "Check native C/C++ libraries, unsafe pointers, or corrupt shared memory objects."
			evidence.ErrorClass = "SIGSEGV"
			return diagnosis, evidence

		case 134: // SIGABRT (128 + 6)
			diagnosis.Category = "Application"
			diagnosis.RootCause = "NativeAbort"
			diagnosis.Confidence = "High"
			diagnosis.Summary = "Process aborted by SIGABRT (Exit code 134), often caused by glibc assertion or panic in native code."
			diagnosis.RecommendedAction = "Check native assertions or check if application called abort()."
			evidence.ErrorClass = "SIGABRT"
			return diagnosis, evidence

		case 1:
			diagnosis.Category = "Application"
			diagnosis.RootCause = "ApplicationRuntimeError"
			diagnosis.Confidence = "Medium"
			diagnosis.Summary = "Application process exited with general error code 1."
			diagnosis.RecommendedAction = "Inspect standard error stream in container logs for unhandled application exceptions."
			return diagnosis, evidence

		case 0:
			diagnosis.Category = "Application"
			diagnosis.RootCause = "ProcessExitedNormally"
			diagnosis.Confidence = "Medium"
			diagnosis.Summary = "Container main process completed execution with exit code 0 without maintaining a persistent foreground daemon."
			diagnosis.RecommendedAction = "Ensure entrypoint command runs in foreground (e.g. nginx -g 'daemon off;' instead of nginx)."
			return diagnosis, evidence

		default:
			diagnosis.Category = "Unknown"
			diagnosis.RootCause = "UnclassifiedExitCode"
			diagnosis.Confidence = "Low"
			diagnosis.Summary = fmt.Sprintf("Container terminated with exit code %d (Reason: %s).", termState.ExitCode, termState.Reason)
			diagnosis.RecommendedAction = fmt.Sprintf("Check application documentation for specific meaning of exit code %d.", termState.ExitCode)
			return diagnosis, evidence
		}
	}

	// Completely Unknown
	diagnosis.Category = "Unknown"
	diagnosis.RootCause = "Unknown"
	diagnosis.Confidence = "Low"
	diagnosis.Summary = "Unable to determine root cause from available metrics, events, or logs."
	diagnosis.RecommendedAction = "Enable debug logging in container and verify cluster monitoring."
	return diagnosis, evidence
}

func hasMemoryLimit(pod *corev1.Pod, containerName string) bool {
	if pod == nil {
		return false
	}
	for _, c := range pod.Spec.Containers {
		if c.Name == containerName {
			if _, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
				return true
			}
		}
	}
	return false
}

func containsMemoryKeywords(logs string) bool {
	lower := strings.ToLower(logs)
	return strings.Contains(lower, "outofmemory") ||
		strings.Contains(lower, "heap space") ||
		strings.Contains(lower, "memoryerror") ||
		strings.Contains(lower, "out of memory")
}
