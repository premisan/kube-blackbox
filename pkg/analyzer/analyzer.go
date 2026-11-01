package analyzer

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
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
	Language        string // Target localization language ("en", "ko", etc.)
}

// Diagnose evaluates container termination status, events, logs, pod specs, and sidecar cascades.
func (e *DiagnosticEngine) Diagnose(input DiagnosticInput) (observerv1alpha1.Diagnosis, observerv1alpha1.Evidence) {
	var evidence observerv1alpha1.Evidence
	var diagnosis observerv1alpha1.Diagnosis

	lang := input.Language
	if lang == "" {
		lang = "ko"
	}

	cs := input.ContainerStatus
	if cs == nil {
		setDiag(&diagnosis, "Unknown", "Unknown", "Low", "No container status available", "Ensure container exists in pod status", lang, "")
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
		if !termState.StartedAt.IsZero() {
			diff := termState.FinishedAt.Sub(termState.StartedAt.Time).Seconds()
			if diff >= 0 {
				secs := int64(diff)
				evidence.UptimeSeconds = &secs
			}
		}
	}

	// Multi-dimensional: Resource spec & SecurityContext inspection
	var matchedContainer *corev1.Container
	if input.Pod != nil {
		for i := range input.Pod.Spec.Containers {
			if input.Pod.Spec.Containers[i].Name == input.ContainerName {
				matchedContainer = &input.Pod.Spec.Containers[i]
				break
			}
		}
		if matchedContainer == nil {
			for i := range input.Pod.Spec.InitContainers {
				if input.Pod.Spec.InitContainers[i].Name == input.ContainerName {
					matchedContainer = &input.Pod.Spec.InitContainers[i]
					break
				}
			}
		}
	}

	if matchedContainer != nil {
		var resParts []string
		if !matchedContainer.Resources.Limits.Cpu().IsZero() {
			resParts = append(resParts, fmt.Sprintf("CPULimit: %s", matchedContainer.Resources.Limits.Cpu().String()))
		}
		if !matchedContainer.Resources.Limits.Memory().IsZero() {
			resParts = append(resParts, fmt.Sprintf("MemLimit: %s", matchedContainer.Resources.Limits.Memory().String()))
		}
		if !matchedContainer.Resources.Requests.Memory().IsZero() {
			resParts = append(resParts, fmt.Sprintf("MemReq: %s", matchedContainer.Resources.Requests.Memory().String()))
		}
		if len(resParts) > 0 {
			evidence.ResourceConstraints = strings.Join(resParts, ", ")
		}

		var scViolations []string
		if matchedContainer.SecurityContext != nil && matchedContainer.SecurityContext.ReadOnlyRootFilesystem != nil && *matchedContainer.SecurityContext.ReadOnlyRootFilesystem {
			if strings.Contains(strings.ToLower(input.PreviousLogs), "read-only file system") || strings.Contains(strings.ToLower(input.PreviousLogs), "erofs") {
				scViolations = append(scViolations, "ReadOnlyRootFilesystemViolation")
			}
		}
		isRunAsNonRoot := false
		if (matchedContainer.SecurityContext != nil && matchedContainer.SecurityContext.RunAsNonRoot != nil && *matchedContainer.SecurityContext.RunAsNonRoot) ||
			(input.Pod.Spec.SecurityContext != nil && input.Pod.Spec.SecurityContext.RunAsNonRoot != nil && *input.Pod.Spec.SecurityContext.RunAsNonRoot) {
			isRunAsNonRoot = true
		}
		if isRunAsNonRoot && (strings.Contains(strings.ToLower(input.PreviousLogs), "permission denied") || (termState != nil && termState.ExitCode == 126)) {
			scViolations = append(scViolations, "RunAsNonRootPermissionViolation")
		}
		if len(scViolations) > 0 {
			evidence.SecurityContextViolations = strings.Join(scViolations, ", ")
		}
	}

	// 1. Analyze Events
	eventRes := AnalyzeEvents(input.Events, input.ContainerName, restartedAt)
	if eventRes != nil {
		evidence.MatchedEvents = eventRes.MatchedEvents
	}

	// Multi-dimensional: Grace Period Exceedance Evaluation
	graceSec := int64(30)
	if input.Pod != nil && input.Pod.Spec.TerminationGracePeriodSeconds != nil {
		graceSec = *input.Pod.Spec.TerminationGracePeriodSeconds
	}
	if termState != nil && termState.ExitCode == 137 && termState.Reason != "OOMKilled" {
		if evidence.UptimeSeconds != nil && *evidence.UptimeSeconds >= graceSec {
			if eventRes == nil || len(eventRes.MatchedEvents) == 0 {
				evidence.GracePeriodExceeded = true
			}
		}
	}

	// 2. Analyze Logs
	logRes := AnalyzeLogs(input.PreviousLogs)
	if logRes != nil {
		evidence.LastLogSnippet = logRes.Snippet
		evidence.MatchedLogPattern = logRes.MatchedPattern
		evidence.ErrorClass = logRes.ErrorClass
		evidence.ErrorLocation = logRes.ErrorLocation
		evidence.CulpritCode = logRes.CulpritCode
	}

	// 3. Sidecar & InitContainer Cascade Analysis
	sidecarRes := AnalyzeSidecarCascade(input.Pod, input.ContainerName, input.PreviousLogs)
	if sidecarRes != nil && sidecarRes.CascadeDetected {
		evidence.SidecarCascade = sidecarRes.Description
	}

	// ==================== Step 1: Explicit Kernel & Runtime Termination ====================
	if termState != nil {
		// OOMKilled by cgroup/kernel
		if termState.Reason == "OOMKilled" || (termState.ExitCode == 137 && termState.Reason == "OOMKilled") {
			setDiag(&diagnosis, "Infrastructure", "OOMKilled", "High",
				"Container exceeded memory limit and was killed by Linux kernel OOM killer (cgroup memory exhaustion).",
				"Increase memory limit in pod spec (resources.limits.memory) or analyze memory leaks.",
				lang, "")
			evidence.ErrorClass = "LinuxOOMKiller"
			return diagnosis, evidence
		}

		// Exit code 126: Permission denied
		if termState.ExitCode == 126 {
			setDiag(&diagnosis, "Configuration", "PermissionDenied", "High",
				"Container entrypoint binary lacks execute permission (Exit code 126).",
				"Add execution permissions (chmod +x) to entrypoint binary/script in Dockerfile.",
				lang, "")
			evidence.ErrorClass = "ExecPermissionDenied"
			return diagnosis, evidence
		}

		// Exit code 127: Command not found
		if termState.ExitCode == 127 {
			setDiag(&diagnosis, "Configuration", "CommandNotFound", "High",
				"Container entrypoint executable or command was not found in image PATH (Exit code 127).",
				"Verify entrypoint path in Dockerfile and ensure required shell/binaries exist in base image.",
				lang, "")
			evidence.ErrorClass = "BinaryNotFound"
			return diagnosis, evidence
		}
	}

	// ==================== Step 2: InitContainer & Sidecar Cascade Prioritization ====================
	if sidecarRes != nil && sidecarRes.CascadeDetected {
		if sidecarRes.IsInitContainer {
			setDiag(&diagnosis, "Infrastructure", "InitContainerFailed", "High",
				fmt.Sprintf("Application container unable to start due to initContainer '%s' failure.", sidecarRes.SidecarName),
				fmt.Sprintf("Inspect logs and termination reason of initContainer '%s'.", sidecarRes.SidecarName),
				lang, sidecarRes.SidecarName)
			evidence.ErrorClass = "InitContainerFailure"
			return diagnosis, evidence
		}

		if sidecarRes.IsStartupRace {
			setDiag(&diagnosis, "Dependency", "IstioStartupRaceCondition", "High",
				fmt.Sprintf("Application container '%s' crashed due to startup race before sidecar '%s' reached Ready state.", input.ContainerName, sidecarRes.SidecarName),
				fmt.Sprintf("Configure 'holdApplicationUntilProxyStarts: true' or adopt K8s 1.28+ native sidecar containers."),
				lang, sidecarRes.SidecarName)
			evidence.ErrorClass = "StartupRaceCondition"
			return diagnosis, evidence
		}

		// If connection refused or no logs and sidecar crashed
		if logRes == nil || logRes.MatchedRule == nil ||
			logRes.MatchedRule.RootCause == "ConnectionRefused" ||
			logRes.MatchedRule.RootCause == "TCPConnectionRefused" ||
			logRes.MatchedRule.RootCause == "NginxBadGatewayUpstream" ||
			logRes.MatchedRule.RootCause == "EnvoyNoHealthyUpstream" {
			setDiag(&diagnosis, "Dependency", "SidecarCascadeFailure", "High",
				fmt.Sprintf("Container failure correlated with crash or unready state of peer sidecar '%s'.", sidecarRes.SidecarName),
				fmt.Sprintf("Check health, logs, and configuration of sidecar '%s'.", sidecarRes.SidecarName),
				lang, sidecarRes.SidecarName)
			evidence.ErrorClass = "SidecarCascade"
			return diagnosis, evidence
		}
	}

	// ==================== Step 3: Kubernetes Events Correlation ====================
	if eventRes != nil && eventRes.MatchedRule != nil {
		setDiag(&diagnosis, eventRes.Category, eventRes.MatchedRule.RootCause, eventRes.MatchedRule.Confidence,
			eventRes.Summary, eventRes.RecommendedAction, lang, "")

		// Multi-dimensional: Check if Liveness failure was compounded by CPU throttling
		if eventRes.MatchedRule.RootCause == "LivenessProbeFailure" && matchedContainer != nil && !matchedContainer.Resources.Limits.Cpu().IsZero() {
			millis := matchedContainer.Resources.Limits.Cpu().MilliValue()
			if millis > 0 && millis <= 300 {
				if lang == "ko" {
					diagnosis.Summary = fmt.Sprintf("%s (낮은 CPU 제한 %dm 설정으로 인한 CFS Throttling 위험 동반)", diagnosis.Summary, millis)
					diagnosis.RecommendedAction = fmt.Sprintf("%s 또한 Throttling 방지를 위해 CPU Limit 증설을 검토하세요.", diagnosis.RecommendedAction)
				} else {
					diagnosis.Summary = fmt.Sprintf("%s (Compounded by tight CPU limit %dm, risking CFS throttling)", diagnosis.Summary, millis)
					diagnosis.RecommendedAction = fmt.Sprintf("%s Also consider increasing container CPU limit.", diagnosis.RecommendedAction)
				}
			}
		}

		return diagnosis, evidence
	}

	// ==================== Step 4: Deep Log Signature Pattern Matching ====================
	if logRes != nil && logRes.MatchedRule != nil {
		detailForI18n := logRes.ErrorLocation
		if logRes.ErrorClass != "" && logRes.ErrorClass != "PythonException" && logRes.ErrorClass != "FatalError" {
			detailForI18n = logRes.ErrorClass
		}
		setDiag(&diagnosis, logRes.Category, logRes.MatchedRule.RootCause, logRes.MatchedRule.Confidence,
			logRes.Summary, logRes.MatchedRule.RecommendedAction, lang, detailForI18n)
		return diagnosis, evidence
	}

	// ==================== Step 4.5: SecurityContext Constraint Violations ====================
	if strings.Contains(evidence.SecurityContextViolations, "ReadOnlyRootFilesystemViolation") {
		setDiag(&diagnosis, "Configuration", "ReadOnlyRootFilesystem", "High",
			"Application attempted to write to filesystem with readOnlyRootFilesystem enabled.",
			"Check pod securityContext and mount emptyDir volumes for writable directories such as /tmp.",
			lang, "")
		evidence.ErrorClass = "EROFS"
		return diagnosis, evidence
	}

	// ==================== Step 5: Combined Heuristic Reasoning ====================
	if termState != nil {
		switch termState.ExitCode {
		case 137: // SIGKILL (128 + 9)
			// Multi-dimensional: Grace Period Exceedance during graceful shutdown
			if evidence.GracePeriodExceeded {
				setDiag(&diagnosis, "Infrastructure", "GracefulShutdownTimeout", "High",
					fmt.Sprintf("Process failed to terminate within terminationGracePeriodSeconds (%ds) after SIGTERM and was forcefully killed with SIGKILL (137).", graceSec),
					"Optimize preStop hooks, drain connections faster in SIGTERM handler, or increase terminationGracePeriodSeconds in pod spec.",
					lang, fmt.Sprintf("%ds", graceSec))
				evidence.ErrorClass = "GracePeriodTimeout"
				return diagnosis, evidence
			}

			if hasMemoryLimit(input.Pod, input.ContainerName) && containsMemoryKeywords(input.PreviousLogs) {
				setDiag(&diagnosis, "Infrastructure", "ProbableOOMKilled", "High",
					"Container killed with SIGKILL (137) with memory limit defined and memory exhaustion indicators in log.",
					"Increase pod memory limit (resources.limits.memory) or optimize memory consumption.",
					lang, "")
				evidence.ErrorClass = "ProbableOOM"
				return diagnosis, evidence
			}

			setDiag(&diagnosis, "Infrastructure", "SigkillTerminated", "Medium",
				"Process killed by SIGKILL (Exit code 137). Typically unrecorded OOM, probe timeout, or forced eviction.",
				"Inspect node dmesg logs for OOM killer events or check if liveness probes timed out.",
				lang, "")
			return diagnosis, evidence

		case 143: // SIGTERM (128 + 15)
			setDiag(&diagnosis, "Infrastructure", "SigtermShutdown", "Medium",
				"Process received SIGTERM (Exit code 143) and terminated gracefully during deployment rollout, scaling, or node drain.",
				"Normal during pod recreation. If unexpected, check deployment revision history or node maintenance.",
				lang, "")
			return diagnosis, evidence

		case 139: // SIGSEGV (128 + 11)
			setDiag(&diagnosis, "Application", "SegmentationFault", "High",
				"Process crashed due to segmentation fault (SIGSEGV, Exit code 139).",
				"Check native C/C++ libraries, unsafe pointers, or corrupt shared memory objects.",
				lang, "")
			evidence.ErrorClass = "SIGSEGV"
			return diagnosis, evidence

		case 135: // SIGBUS (128 + 7)
			setDiag(&diagnosis, "Application", "BusError", "High",
				"Process crashed due to Bus Error (SIGBUS, Exit code 135).",
				"Check mmap file boundaries, alignment issues, or network-mounted binary execution.",
				lang, "")
			evidence.ErrorClass = "SIGBUS"
			return diagnosis, evidence

		case 134: // SIGABRT (128 + 6)
			setDiag(&diagnosis, "Application", "NativeAbort", "High",
				"Process aborted by SIGABRT (Exit code 134), often caused by glibc assertion or panic in native code.",
				"Check native assertions or check if application called abort().",
				lang, "")
			evidence.ErrorClass = "SIGABRT"
			return diagnosis, evidence

		case 1:
			setDiag(&diagnosis, "Application", "ApplicationRuntimeError", "Medium",
				"Application process exited with general error code 1.",
				"Inspect standard error stream in container logs for unhandled application exceptions.",
				lang, "")
			return diagnosis, evidence

		case 0:
			setDiag(&diagnosis, "Application", "ProcessExitedNormally", "Medium",
				"Container main process completed execution with exit code 0 without maintaining a persistent foreground daemon.",
				"Ensure entrypoint command runs in foreground (e.g. nginx -g 'daemon off;' instead of nginx).",
				lang, "")
			return diagnosis, evidence

		default:
			summary := fmt.Sprintf("Container terminated with exit code %d (Reason: %s).", termState.ExitCode, termState.Reason)
			recAction := fmt.Sprintf("Check application documentation for specific meaning of exit code %d.", termState.ExitCode)
			setDiag(&diagnosis, "Unknown", "UnclassifiedExitCode", "Low", summary, recAction, lang, "")
			return diagnosis, evidence
		}
	}

	// Completely Unknown
	setDiag(&diagnosis, "Unknown", "Unknown", "Low",
		"Unable to determine root cause from available metrics, events, or logs.",
		"Enable debug logging in container and verify cluster monitoring.",
		lang, "")
	return diagnosis, evidence
}

func setDiag(d *observerv1alpha1.Diagnosis, category, rootCause, confidence, defaultSummary, defaultAction, lang, detail string) {
	d.Category = category
	d.RootCause = rootCause
	d.Confidence = confidence
	summary, action := Localize(rootCause, lang, defaultSummary, defaultAction, detail)
	d.Summary = summary
	d.RecommendedAction = action
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
