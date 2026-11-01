package synthesizer

import (
	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
)

// SupportedLanguages defines the languages officially supported by the synthesizer
var SupportedLanguages = []string{"ko", "en"}

// IncidentContext bundles all verified facts, logs, and metadata for causal analysis
type IncidentContext struct {
	Namespace         string
	PodName           string
	ContainerName     string
	ExitCode          *int32
	TerminationReason string
	Category          string
	RootCause         string
	Confidence        string
	MatchedEvents     []string
	LastLogs          string
	Language          string // Requested language: "ko", "en"
	CulpritCode       *observerv1alpha1.CulpritCode
}

// InsightResult is the structured diagnostic response containing the root cause chain and actionable fix
type InsightResult struct {
	Engine          string
	Analyzed        bool
	Language        string
	Confidence      string
	InferredContext string
	SuggestedFix    string
	RootCauseChain  []observerv1alpha1.ChainStep
}
