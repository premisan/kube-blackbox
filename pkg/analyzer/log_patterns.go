package analyzer

import (
	"regexp"
	"strings"
)

type LogRule struct {
	Name       string
	RootCause  string
	Confidence string
	Regex      *regexp.Regexp
	SummaryTpl string
}

var logRules = []LogRule{
	{
		Name:       "GoPanic",
		RootCause:  "AppPanic",
		Confidence: "High",
		Regex:      regexp.MustCompile(`(?m)^panic:\s*(.+)$`),
		SummaryTpl: "Go runtime panic detected: %s",
	},
	{
		Name:       "JVMOOM",
		RootCause:  "JVMOOM",
		Confidence: "High",
		Regex:      regexp.MustCompile(`(?m)java\.lang\.OutOfMemoryError:\s*(.+)$`),
		SummaryTpl: "JVM OutOfMemoryError detected: %s",
	},
	{
		Name:       "AddressAlreadyInUse",
		RootCause:  "PortConflict",
		Confidence: "High",
		Regex:      regexp.MustCompile(`(?i)(address already in use|bind: address already in use)`),
		SummaryTpl: "Port binding conflict detected: %s",
	},
	{
		Name:       "FatalError",
		RootCause:  "AppFatalError",
		Confidence: "High",
		Regex:      regexp.MustCompile(`(?i)(?:fatal error:|\[fatal\]|FATAL:\s*)(.+)$`),
		SummaryTpl: "Fatal error detected in application log: %s",
	},
	{
		Name:       "SegmentationFault",
		RootCause:  "SegmentationFault",
		Confidence: "High",
		Regex:      regexp.MustCompile(`(?i)(segmentation fault|SIGSEGV)`),
		SummaryTpl: "Segmentation fault detected in log",
	},
	{
		Name:       "PythonTraceback",
		RootCause:  "AppUnhandledException",
		Confidence: "High",
		Regex:      regexp.MustCompile(`(?m)Traceback \(most recent call last\):`),
		SummaryTpl: "Python unhandled exception traceback detected",
	},
	{
		Name:       "NodeUncaughtException",
		RootCause:  "AppUnhandledException",
		Confidence: "High",
		Regex:      regexp.MustCompile(`(?i)(uncaughtException:|ReferenceError:|TypeError:)`),
		SummaryTpl: "Node.js unhandled exception detected",
	},
	{
		Name:       "ConnectionRefused",
		RootCause:  "DependencyConnectionRefused",
		Confidence: "Medium",
		Regex:      regexp.MustCompile(`(?i)(connection refused|dial tcp.*connect: connection refused)`),
		SummaryTpl: "Dependency connection refused: %s",
	},
}

type LogAnalysisResult struct {
	MatchedRule    *LogRule
	MatchedPattern string
	Snippet        string
	Summary        string
}

// AnalyzeLogs searches previous container logs for known failure patterns.
func AnalyzeLogs(logs string) *LogAnalysisResult {
	if strings.TrimSpace(logs) == "" {
		return nil
	}

	lines := strings.Split(logs, "\n")
	tailSnippet := extractTailSnippet(lines, 10)

	for _, rule := range logRules {
		if loc := rule.Regex.FindStringSubmatch(logs); len(loc) > 0 {
			matched := loc[0]
			detail := matched
			if len(loc) > 1 && loc[1] != "" {
				detail = strings.TrimSpace(loc[1])
			}

			summary := rule.SummaryTpl
			if strings.Contains(rule.SummaryTpl, "%s") {
				summary = strings.Replace(rule.SummaryTpl, "%s", truncateString(detail, 80), 1)
			}

			return &LogAnalysisResult{
				MatchedRule:    &rule,
				MatchedPattern: rule.Name,
				Snippet:        tailSnippet,
				Summary:        summary,
			}
		}
	}

	return &LogAnalysisResult{
		MatchedRule:    nil,
		MatchedPattern: "",
		Snippet:        tailSnippet,
		Summary:        "",
	}
}

func extractTailSnippet(lines []string, n int) string {
	if len(lines) == 0 {
		return ""
	}
	start := len(lines) - n
	if start < 0 {
		start = 0
	}
	return strings.TrimSpace(strings.Join(lines[start:], "\n"))
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
