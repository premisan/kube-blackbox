package analyzer

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// SidecarAnalysisResult holds findings if a sidecar or initContainer failure impacted the container.
type SidecarAnalysisResult struct {
	CascadeDetected bool
	SidecarName     string
	IsInitContainer bool
	IsStartupRace   bool
	Description     string
}

// AnalyzeSidecarCascade checks if other containers (sidecars or initContainers) in the pod
// experienced restarts or failures that cascade into the current container.
func AnalyzeSidecarCascade(pod *corev1.Pod, currentContainerName string, currentLogs string) *SidecarAnalysisResult {
	if pod == nil {
		return nil
	}

	// 1. Check InitContainers: If an init container failed, app containers can never start or will fail
	for _, ic := range pod.Status.InitContainerStatuses {
		if ic.LastTerminationState.Terminated != nil && ic.LastTerminationState.Terminated.ExitCode != 0 {
			return &SidecarAnalysisResult{
				CascadeDetected: true,
				SidecarName:     ic.Name,
				IsInitContainer: true,
				Description:     fmt.Sprintf("Init container '%s' failed with exit code %d (Reason: %s)", ic.Name, ic.LastTerminationState.Terminated.ExitCode, ic.LastTerminationState.Terminated.Reason),
			}
		}
		if ic.State.Waiting != nil && (ic.State.Waiting.Reason == "CrashLoopBackOff" || ic.State.Waiting.Reason == "Error") {
			return &SidecarAnalysisResult{
				CascadeDetected: true,
				SidecarName:     ic.Name,
				IsInitContainer: true,
				Description:     fmt.Sprintf("Init container '%s' is failing in state Waiting (%s: %s)", ic.Name, ic.State.Waiting.Reason, ic.State.Waiting.Message),
			}
		}
	}

	// 2. Check Other App Containers / Sidecars
	lowerLogs := strings.ToLower(currentLogs)
	hasLocalhostRefusal := strings.Contains(lowerLogs, "127.0.0.1") ||
		strings.Contains(lowerLogs, "localhost") ||
		strings.Contains(lowerLogs, "connection refused") ||
		strings.Contains(lowerLogs, "connect: connection refused") ||
		strings.Contains(lowerLogs, "econnrefused") ||
		strings.Contains(lowerLogs, "proxy")

	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == currentContainerName {
			continue
		}

		isAbnormal := false
		detail := ""
		if cs.LastTerminationState.Terminated != nil && cs.LastTerminationState.Terminated.ExitCode != 0 {
			isAbnormal = true
			detail = fmt.Sprintf("terminated with exit code %d (Reason: %s)", cs.LastTerminationState.Terminated.ExitCode, cs.LastTerminationState.Terminated.Reason)
		} else if cs.State.Waiting != nil && (cs.State.Waiting.Reason == "CrashLoopBackOff" || cs.State.Waiting.Reason == "Error") {
			isAbnormal = true
			detail = fmt.Sprintf("in CrashLoopBackOff (%s)", cs.State.Waiting.Message)
		} else if cs.RestartCount > 0 && !cs.Ready {
			isAbnormal = true
			detail = fmt.Sprintf("restarted %d times and is not Ready", cs.RestartCount)
		}

		isKnownSidecar := isProxyOrSidecar(cs.Name)
		if isAbnormal {
			if hasLocalhostRefusal || isKnownSidecar {
				return &SidecarAnalysisResult{
					CascadeDetected: true,
					SidecarName:     cs.Name,
					IsInitContainer: false,
					Description:     fmt.Sprintf("Sidecar/peer '%s' %s, cascading failure into '%s'", cs.Name, detail, currentContainerName),
				}
			}
		}

		// Startup race condition check: main container crashed due to connection refusal while sidecar was not yet Ready
		if isKnownSidecar && (hasLocalhostRefusal || strings.Contains(lowerLogs, "15021")) && !cs.Ready {
			return &SidecarAnalysisResult{
				CascadeDetected: true,
				SidecarName:     cs.Name,
				IsInitContainer: false,
				IsStartupRace:   true,
				Description:     fmt.Sprintf("Startup Race Condition: main container '%s' initiated network connections before sidecar '%s' reached Ready status", currentContainerName, cs.Name),
			}
		}
	}

	return nil
}

func isProxyOrSidecar(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "proxy") ||
		strings.Contains(lower, "sidecar") ||
		strings.Contains(lower, "agent") ||
		strings.Contains(lower, "envoy") ||
		strings.Contains(lower, "istio") ||
		strings.Contains(lower, "linkerd") ||
		strings.Contains(lower, "vault") ||
		strings.Contains(lower, "sql-proxy") ||
		strings.Contains(lower, "fluent") ||
		strings.Contains(lower, "datadog")
}
