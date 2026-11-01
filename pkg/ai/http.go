package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
)

// HTTPOllamaEngine invokes an external OpenAI-compatible or Ollama chat endpoint (/v1/chat/completions)
// with fact-anchored prompt guardrails, and safely falls back to EmbeddedEngine if unreachable.
type HTTPOllamaEngine struct {
	endpoint string
	model    string
	apiKey   string
	timeout  time.Duration
	client   *http.Client
	fallback *EmbeddedEngine
}

func NewHTTPOllamaEngine(endpoint, model, apiKey string, timeoutSeconds int) *HTTPOllamaEngine {
	if endpoint == "" {
		endpoint = "http://localhost:11434/v1"
	}
	if model == "" {
		model = "qwen2.5-coder:0.5b"
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 12
	}
	timeout := time.Duration(timeoutSeconds) * time.Second

	return &HTTPOllamaEngine{
		endpoint: strings.TrimRight(endpoint, "/"),
		model:    model,
		apiKey:   apiKey,
		timeout:  timeout,
		client:   &http.Client{Timeout: timeout},
		fallback: NewEmbeddedEngine("embedded-fallback"),
	}
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model          string        `json:"model"`
	Messages       []chatMessage `json:"messages"`
	Temperature    float32       `json:"temperature"`
	ResponseFormat *respFormat   `json:"response_format,omitempty"`
}

type respFormat struct {
	Type string `json:"type"`
}

type chatChoice struct {
	Message chatMessage `json:"message"`
}

type chatResponse struct {
	Choices []chatChoice `json:"choices"`
}

type aiResponseSchema struct {
	InferredContext string   `json:"inferredContext"`
	SuggestedFix    string   `json:"suggestedFix"`
	RootCauseChain  []string `json:"rootCauseChain"`
}

func (h *HTTPOllamaEngine) Analyze(ctx context.Context, incident IncidentContext) (*AIInsightResult, error) {
	lang := incident.Language
	if lang == "" {
		lang = "en"
	}

	exitCodeStr := "Unknown"
	if incident.ExitCode != nil {
		exitCodeStr = fmt.Sprintf("%d", *incident.ExitCode)
	}

	systemPrompt := fmt.Sprintf(`You are a Kubernetes incident diagnosis copilot.
Your job is to analyze the container crash context and explain the failure chain and fix recommendations.
CRITICAL CONSTRAINTS:
1. You MUST output STRICT VALID JSON matching this schema:
   {"inferredContext": "string", "suggestedFix": "string", "rootCauseChain": ["step 1", "step 2", "step 3"]}
2. You MUST write all explanations strictly in the requested target language: %s.
3. The root cause '%s' and exit code '%s' are immutable facts. Do NOT hallucinate conflicting causes.`,
		lang, incident.RootCause, exitCodeStr)

	userPrompt := fmt.Sprintf(`[Crash Facts]
- Target Language: %s
- Pod: %s/%s
- Container: %s
- Exit Code: %s
- Termination Reason: %s
- Root Cause: %s
- Category: %s
- Matched Events: %v
- Recent Log Snippet:
%s

Generate concise JSON explanation:`,
		lang, incident.Namespace, incident.PodName, incident.ContainerName, exitCodeStr,
		incident.TerminationReason, incident.RootCause, incident.Category,
		incident.MatchedEvents, truncateLogs(incident.LastLogs, 1500))

	reqBody := chatRequest{
		Model: h.model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature:    0.2,
		ResponseFormat: &respFormat{Type: "json_object"},
	}

	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return h.fallback.Analyze(ctx, incident)
	}

	apiURL := fmt.Sprintf("%s/chat/completions", h.endpoint)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return h.fallback.Analyze(ctx, incident)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if h.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+h.apiKey)
	}

	resp, err := h.client.Do(httpReq)
	if err != nil || resp.StatusCode != http.StatusOK {
		// Graceful fallback to embedded analyzer
		return h.fallback.Analyze(ctx, incident)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return h.fallback.Analyze(ctx, incident)
	}

	var chatResp chatResponse
	if err := json.Unmarshal(bodyBytes, &chatResp); err != nil || len(chatResp.Choices) == 0 {
		return h.fallback.Analyze(ctx, incident)
	}

	content := strings.TrimSpace(chatResp.Choices[0].Message.Content)
	var parsed aiResponseSchema
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return h.fallback.Analyze(ctx, incident)
	}

	var chain []observerv1alpha1.ChainStep
	for i, step := range parsed.RootCauseChain {
		chain = append(chain, observerv1alpha1.ChainStep{
			Step:        i + 1,
			Description: step,
		})
	}
	if len(chain) == 0 {
		chain = buildRootCauseChain(incident, lang)
	}

	return &AIInsightResult{
		Model:           h.model,
		Analyzed:        true,
		Language:        lang,
		Confidence:      incident.Confidence,
		InferredContext: parsed.InferredContext,
		SuggestedFix:    parsed.SuggestedFix,
		RootCauseChain:  chain,
	}, nil
}

func truncateLogs(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[len(s)-max:]
}
