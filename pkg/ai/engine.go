package ai

import "context"

// AIEngine defines the contract for analyzing an incident and yielding high-level insights.
type AIEngine interface {
	Analyze(ctx context.Context, incident IncidentContext) (*AIInsightResult, error)
}

// NewEngine creates an AIEngine instance based on the provided configuration.
func NewEngine(cfg Config) AIEngine {
	if !cfg.Enabled {
		return nil
	}

	provider := cfg.Provider
	if provider == "" {
		provider = "embedded"
	}

	switch provider {
	case "ollama", "http", "openai":
		return NewHTTPOllamaEngine(cfg.Endpoint, cfg.Model, cfg.APIKey, cfg.TimeoutSeconds)
	case "embedded":
		fallthrough
	default:
		modelName := cfg.Model
		if modelName == "" {
			modelName = "embedded-semantic-analyzer"
		}
		return NewEmbeddedEngine(modelName)
	}
}
