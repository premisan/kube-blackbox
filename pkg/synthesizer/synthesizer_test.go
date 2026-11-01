package synthesizer

import (
	"context"
	"strings"
	"testing"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
)

func TestSynthesizer_Korean(t *testing.T) {
	s := NewSynthesizer()
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

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Analyzed {
		t.Fatalf("expected Analyzed=true")
	}
	if result.Engine != EngineIdentifier {
		t.Fatalf("expected Engine=%s, got %s", EngineIdentifier, result.Engine)
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

func TestSynthesizer_UnsupportedLanguageFallback(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(137)

	incident := IncidentContext{
		Namespace:     "default",
		PodName:       "app",
		ContainerName: "app",
		ExitCode:      &exitCode,
		RootCause:     "OOMKilled",
		Language:      "cn", // Unsupported language
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Language, "fallback from cn") {
		t.Fatalf("expected fallback record in language, got: %s", result.Language)
	}
}

func TestSynthesizer_CulpritCode(t *testing.T) {
	s := NewSynthesizer()
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

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	foundCulprit := false
	for _, step := range result.RootCauseChain {
		if strings.Contains(step.Description, "process.go:77") {
			foundCulprit = true
			break
		}
	}
	if !foundCulprit {
		t.Fatalf("expected culprit code mentioned in RootCauseChain, got: %v", result.RootCauseChain)
	}
}

func TestSynthesizer_SidecarCascade(t *testing.T) {
	s := NewSynthesizer()
	exitCode := int32(1)

	incident := IncidentContext{
		Namespace:     "production",
		PodName:       "payment-api",
		ContainerName: "payment-api",
		ExitCode:      &exitCode,
		RootCause:     "SidecarCascadeFailure",
		Category:      "Dependency",
		Confidence:    "High",
		Language:      "ko",
	}

	result, err := s.Synthesize(context.Background(), incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RootCauseChain) == 0 {
		t.Fatalf("expected RootCauseChain for SidecarCascadeFailure")
	}
	if !strings.Contains(result.InferredContext, "사이드카") {
		t.Fatalf("expected InferredContext to mention sidecar, got: %s", result.InferredContext)
	}
}

