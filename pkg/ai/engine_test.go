package ai

import (
	"context"
	"testing"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
)

func TestEmbeddedEngine_Analyze_Korean(t *testing.T) {
	engine := NewEmbeddedEngine("test-model")
	exitCode := int32(137)

	incident := IncidentContext{
		Namespace:     "default",
		PodName:       "payment-service-1234",
		ContainerName: "payment-worker",
		ExitCode:      &exitCode,
		RootCause:     "OOMKilled",
		Category:      "Infrastructure",
		Confidence:    "High",
		Language:      "ko",
	}

	result, err := engine.Analyze(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Analyzed {
		t.Fatalf("expected Analyzed=true")
	}
	if result.Language != "ko" {
		t.Fatalf("expected Language=ko, got %s", result.Language)
	}
	if len(result.RootCauseChain) == 0 {
		t.Fatalf("expected non-empty RootCauseChain")
	}
	if result.InferredContext == "" || result.SuggestedFix == "" {
		t.Fatalf("expected InferredContext and SuggestedFix, got empty")
	}
}

func TestEmbeddedEngine_Analyze_CulpritCode(t *testing.T) {
	engine := NewEmbeddedEngine("test-model")
	exitCode := int32(2)

	incident := IncidentContext{
		Namespace:     "default",
		PodName:       "go-worker",
		ContainerName: "worker",
		ExitCode:      &exitCode,
		RootCause:     "GoPanic",
		Category:      "Application",
		Confidence:    "High",
		Language:      "en",
		CulpritCode: &observerv1alpha1.CulpritCode{
			Language: "Go",
			File:     "process.go",
			Line:     77,
		},
	}

	result, err := engine.Analyze(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify that culprit code is referenced in RootCauseChain
	foundCulprit := false
	for _, step := range result.RootCauseChain {
		if step.Description != "" && (containsSubstr(step.Description, "process.go:77") || containsSubstr(step.Description, "process.go")) {
			foundCulprit = true
			break
		}
	}
	if !foundCulprit {
		t.Fatalf("expected culprit code mentioned in RootCauseChain, got: %v", result.RootCauseChain)
	}
}

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(s) > 0 && len(sub) > 0 && (s[:len(sub)] == sub || containsSubstr(s[1:], sub))))
}
