package analyzer

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

type EventRule struct {
	Name       string
	RootCause  string
	Confidence string
	SummaryTpl string
	Match      func(evt corev1.Event, containerName string) bool
}

var eventRules = []EventRule{
	{
		Name:       "LivenessProbeFailed",
		RootCause:  "LivenessProbeFailure",
		Confidence: "High",
		SummaryTpl: "Container failed liveness probe: %s",
		Match: func(evt corev1.Event, containerName string) bool {
			msg := evt.Message
			return (evt.Reason == "Unhealthy" || evt.Reason == "Killing") &&
				strings.Contains(strings.ToLower(msg), "liveness probe failed") &&
				(containerName == "" || strings.Contains(msg, containerName) || evt.InvolvedObject.FieldPath == "" || strings.Contains(evt.InvolvedObject.FieldPath, containerName))
		},
	},
	{
		Name:       "StartupProbeFailed",
		RootCause:  "StartupProbeFailure",
		Confidence: "High",
		SummaryTpl: "Container failed startup probe: %s",
		Match: func(evt corev1.Event, containerName string) bool {
			msg := evt.Message
			return (evt.Reason == "Unhealthy" || evt.Reason == "Killing") &&
				strings.Contains(strings.ToLower(msg), "startup probe failed") &&
				(containerName == "" || strings.Contains(msg, containerName) || evt.InvolvedObject.FieldPath == "" || strings.Contains(evt.InvolvedObject.FieldPath, containerName))
		},
	},
	{
		Name:       "NodeEviction",
		RootCause:  "NodeEviction",
		Confidence: "High",
		SummaryTpl: "Pod evicted due to node pressure: %s",
		Match: func(evt corev1.Event, containerName string) bool {
			return evt.Reason == "Evicted" ||
				strings.Contains(evt.Message, "low on resource") ||
				strings.Contains(evt.Message, "The node was low on resource")
		},
	},
	{
		Name:       "Preempted",
		RootCause:  "Preempted",
		Confidence: "High",
		SummaryTpl: "Pod was preempted by higher priority pod: %s",
		Match: func(evt corev1.Event, containerName string) bool {
			return evt.Reason == "Preempted" || strings.Contains(evt.Message, "preempted by")
		},
	},
}

type EventAnalysisResult struct {
	MatchedRule   *EventRule
	MatchedEvents []string
	Summary       string
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
						MatchedRule: &rule,
						Summary:     fmt.Sprintf(rule.SummaryTpl, truncateString(evt.Message, 100)),
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
