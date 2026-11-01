package analyzer

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

type EventRule struct {
	Name              string
	Category          string
	RootCause         string
	Confidence        string
	SummaryTpl        string
	RecommendedAction string
	Match             func(evt corev1.Event, containerName string) bool
}

var eventRules = []EventRule{
	{
		Name:              "LivenessProbeFailed",
		Category:          "Infrastructure",
		RootCause:         "LivenessProbeFailure",
		Confidence:        "High",
		SummaryTpl:        "Container failed liveness probe: %s",
		RecommendedAction: "Check application responsiveness, HTTP endpoint health, or increase livenessProbe initialDelaySeconds/timeoutSeconds.",
		Match: func(evt corev1.Event, containerName string) bool {
			msg := evt.Message
			return (evt.Reason == "Unhealthy" || evt.Reason == "Killing") &&
				strings.Contains(strings.ToLower(msg), "liveness probe failed") &&
				(containerName == "" || strings.Contains(msg, containerName) || evt.InvolvedObject.FieldPath == "" || strings.Contains(evt.InvolvedObject.FieldPath, containerName))
		},
	},
	{
		Name:              "StartupProbeFailed",
		Category:          "Infrastructure",
		RootCause:         "StartupProbeFailure",
		Confidence:        "High",
		SummaryTpl:        "Container failed startup probe: %s",
		RecommendedAction: "Application takes longer to boot than configured. Increase startupProbe failureThreshold or periodSeconds.",
		Match: func(evt corev1.Event, containerName string) bool {
			msg := evt.Message
			return (evt.Reason == "Unhealthy" || evt.Reason == "Killing") &&
				strings.Contains(strings.ToLower(msg), "startup probe failed") &&
				(containerName == "" || strings.Contains(msg, containerName) || evt.InvolvedObject.FieldPath == "" || strings.Contains(evt.InvolvedObject.FieldPath, containerName))
		},
	},
	{
		Name:              "NodeEviction",
		Category:          "Infrastructure",
		RootCause:         "NodeEviction",
		Confidence:        "High",
		SummaryTpl:        "Pod evicted due to node resource pressure: %s",
		RecommendedAction: "Node ran out of disk or memory. Verify node resources (kubectl describe node) or increase node cluster capacity.",
		Match: func(evt corev1.Event, containerName string) bool {
			return evt.Reason == "Evicted" ||
				strings.Contains(evt.Message, "low on resource") ||
				strings.Contains(evt.Message, "The node was low on resource")
		},
	},
	{
		Name:              "Preempted",
		Category:          "Infrastructure",
		RootCause:         "Preempted",
		Confidence:        "High",
		SummaryTpl:        "Pod was preempted by higher priority pod: %s",
		RecommendedAction: "Check PriorityClass of other pods in the cluster or assign a dedicated node pool.",
		Match: func(evt corev1.Event, containerName string) bool {
			return evt.Reason == "Preempted" || strings.Contains(evt.Message, "preempted by")
		},
	},
	{
		Name:              "FailedMountVolume",
		Category:          "Infrastructure",
		RootCause:         "VolumeMountFailure",
		Confidence:        "High",
		SummaryTpl:        "Volume mount failed: %s",
		RecommendedAction: "Verify PVC status, storage class provisioner, and node disk attachment limits.",
		Match: func(evt corev1.Event, containerName string) bool {
			return evt.Reason == "FailedMount" || evt.Reason == "FailedAttachVolume"
		},
	},
	{
		Name:              "FailedCreateSandbox",
		Category:          "Infrastructure",
		RootCause:         "PodSandboxConfigFailure",
		Confidence:        "High",
		SummaryTpl:        "Failed to create pod sandbox: %s",
		RecommendedAction: "Check CNI plugin health, IP address exhaustion on the node subnet, or container runtime daemon.",
		Match: func(evt corev1.Event, containerName string) bool {
			return evt.Reason == "FailedCreatePodSandBox"
		},
	},
	{
		Name:              "SystemOOMKilled",
		Category:          "Infrastructure",
		RootCause:         "SystemOOMKilled",
		Confidence:        "High",
		SummaryTpl:        "Kernel or system OOM killer invoked: %s",
		RecommendedAction: "Host or cgroup ran out of memory. Review node memory utilization and container memory limits.",
		Match: func(evt corev1.Event, containerName string) bool {
			lower := strings.ToLower(evt.Message)
			return (evt.Reason == "SystemOOM" || evt.Reason == "OOMKilling") ||
				((evt.Reason == "Killing" || evt.Reason == "Unhealthy") && (strings.Contains(lower, "out of memory") || strings.Contains(lower, "cgroup out of memory")))
		},
	},
	{
		Name:              "NodeMemoryPressure",
		Category:          "Infrastructure",
		RootCause:         "NodeMemoryPressure",
		Confidence:        "High",
		SummaryTpl:        "Node reported MemoryPressure condition: %s",
		RecommendedAction: "Node memory is critically exhausted. Scale out node group or reduce workload memory limits.",
		Match: func(evt corev1.Event, containerName string) bool {
			return strings.Contains(evt.Reason, "MemoryPressure") || strings.Contains(evt.Message, "NodeHasInsufficientMemory")
		},
	},
	{
		Name:              "NodeDiskPressure",
		Category:          "Infrastructure",
		RootCause:         "NodeDiskPressure",
		Confidence:        "High",
		SummaryTpl:        "Node reported DiskPressure condition: %s",
		RecommendedAction: "Node ephemeral storage or root disk is full. Clean up unused container images or expand node disk.",
		Match: func(evt corev1.Event, containerName string) bool {
			return strings.Contains(evt.Reason, "DiskPressure") || strings.Contains(evt.Message, "NodeHasDiskPressure")
		},
	},
}

type EventAnalysisResult struct {
	MatchedRule       *EventRule
	MatchedEvents     []string
	Summary           string
	Category          string
	RecommendedAction string
}

// AnalyzeEvents checks recent events for the target container and returns matched root cause if any.
func AnalyzeEvents(events []corev1.Event, containerName string, restartedAt time.Time) *EventAnalysisResult {
	var matchedStrings []string
	var topResult *EventAnalysisResult

	// Filter and sort events (most recent first)
	for i := len(events) - 1; i >= 0; i-- {
		evt := events[i]

		// Event timestamp check: within a 10-minute window around restartedAt if available
		evtTime := evt.LastTimestamp.Time
		if evtTime.IsZero() {
			evtTime = evt.EventTime.Time
		}
		if !evtTime.IsZero() && !restartedAt.IsZero() {
			diff := evtTime.Sub(restartedAt)
			if diff < -10*time.Minute || diff > 10*time.Minute {
				continue
			}
		}

		formatted := fmt.Sprintf("[%s] %s: %s (count: %d)", evt.Type, evt.Reason, evt.Message, evt.Count)

		for _, rule := range eventRules {
			if rule.Match(evt, containerName) {
				matchedStrings = append(matchedStrings, formatted)
				if topResult == nil {
					topResult = &EventAnalysisResult{
						MatchedRule:       &rule,
						Category:          rule.Category,
						Summary:           fmt.Sprintf(rule.SummaryTpl, truncateString(evt.Message, 100)),
						RecommendedAction: rule.RecommendedAction,
					}
				}
				break
			}
		}
	}

	if topResult != nil {
		topResult.MatchedEvents = matchedStrings
		return topResult
	}

	if len(matchedStrings) > 0 {
		return &EventAnalysisResult{
			MatchedEvents: matchedStrings,
		}
	}

	return nil
}
