package ai

import (
	observerv1alpha1 "github.com/premisan/kube-pinger/api/v1alpha1"
)

// IncidentContext bundles all collected facts, logs, and metadata for AI reasoning
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
	Language          string // e.g. "ko", "en", "ja"
	CulpritCode       *observerv1alpha1.CulpritCode
}

// AIInsightResult is the structured diagnostic response from the AI engine
type AIInsightResult struct {
	Model           string
	Analyzed        bool
	Language        string
	Confidence      string
	InferredContext string
	SuggestedFix    string
	RootCauseChain  []observerv1alpha1.ChainStep
}

// Config configures the AI diagnostic engine
type Config struct {
	Enabled         bool
	Provider        string // "embedded", "ollama", "http", "openai"
	Endpoint        string // e.g. "http://localhost:11434/v1"
	Model           string // e.g. "qwen2.5-coder:0.5b"
	APIKey          string
	DefaultLanguage string // e.g. "en", "ko"
	TimeoutSeconds  int
}
