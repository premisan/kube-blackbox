package analyzer

import (
	"fmt"
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

// Diagnose evaluates container termination status, events, and logs to deduce root cause.
func (e *DiagnosticEngine) Diagnose(input DiagnosticInput) (observerv1alpha1.Diagnosis, observerv1alpha1.Evidence) {
	var evidence observerv1alpha1.Evidence
	var diagnosis observerv1alpha1.Diagnosis

	cs := input.ContainerStatus
	if cs == nil {
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
	}

	// Step 1: Deterministic check on LastTerminationState
	if termState != nil {
		// OOMKilled check
		if termState.Reason == "OOMKilled" || (termState.ExitCode == 137 && termState.Reason == "OOMKilled") {
			diagnosis.RootCause = "OOMKilled"
			diagnosis.Confidence = "High"
			diagnosis.Summary = "Container exceeded memory limit and was terminated by the kernel OOM killer (OOMKilled)."
			return diagnosis, evidence
		}

		// Exit code 126 / 127
		if termState.ExitCode == 126 {
			diagnosis.RootCause = "PermissionDenied"
			diagnosis.Confidence = "High"
			diagnosis.Summary = "Container entrypoint or command lacks execution permission (Exit code 126)."
			return diagnosis, evidence
		}
		if termState.ExitCode == 127 {
			diagnosis.RootCause = "CommandNotFound"
			diagnosis.Confidence = "High"
			diagnosis.Summary = "Container entrypoint binary or command was not found (Exit code 127)."
			return diagnosis, evidence
		}
	}

	// Step 2: Cross-check with Kubernetes Events (Probe failure, Eviction, Preemption)
	if eventRes != nil && eventRes.MatchedRule != nil {
		diagnosis.RootCause = eventRes.MatchedRule.RootCause
		diagnosis.Confidence = eventRes.MatchedRule.Confidence
		diagnosis.Summary = eventRes.Summary
		return diagnosis, evidence
	}

	// Step 3: Check Previous Container Logs for known patterns
	if logRes != nil && logRes.MatchedRule != nil {
		diagnosis.RootCause = logRes.MatchedRule.RootCause
		diagnosis.Confidence = logRes.MatchedRule.Confidence
		diagnosis.Summary = logRes.Summary
		return diagnosis, evidence
	}

	// Step 4: Fallback to ExitCode heuristic mapping
	if termState != nil {
		switch termState.ExitCode {
		case 137:
			diagnosis.RootCause = "SigkillTerminated"
			diagnosis.Confidence = "Medium"
			diagnosis.Summary = "Process killed by SIGKILL (137). Could be unrecorded OOM, probe timeout, or manual pod eviction."
		case 143:
			diagnosis.RootCause = "SigtermShutdown"
			diagnosis.Confidence = "Medium"
			diagnosis.Summary = "Process received SIGTERM (143) and terminated gracefully or timed out during pod rollout/deletion."
		case 139:
			diagnosis.RootCause = "SegmentationFault"
			diagnosis.Confidence = "High"
			diagnosis.Summary = "Process terminated due to segmentation fault (SIGSEGV, Exit code 139)."
		case 1:
			diagnosis.RootCause = "ApplicationRuntimeError"
			diagnosis.Confidence = "Medium"
			diagnosis.Summary = "Application process exited with general error code 1."
		case 0:
			diagnosis.RootCause = "ProcessExitedNormally"
			diagnosis.Confidence = "Medium"
			diagnosis.Summary = "Main process completed execution with exit code 0 without running as a persistent daemon."
		default:
			diagnosis.RootCause = "UnclassifiedExitCode"
			diagnosis.Confidence = "Low"
			diagnosis.Summary = fmt.Sprintf("Container terminated with exit code %d (Reason: %s).", termState.ExitCode, termState.Reason)
		}
		return diagnosis, evidence
	}

	// Completely Unknown
	diagnosis.RootCause = "Unknown"
	diagnosis.Confidence = "Low"
	diagnosis.Summary = "Unable to determine root cause from available metrics, events, or logs."
	return diagnosis, evidence
}
