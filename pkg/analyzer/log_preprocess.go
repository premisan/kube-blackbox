package analyzer

import (
	"encoding/json"
	"strings"
)

// PreprocessLogs inspects container logs and automatically unescapes and normalizes
// structured JSON logs (Zap, Winston, Bunyan, Logstash, Serilog, etc.) into readable text.
func PreprocessLogs(logs string) string {
	if strings.TrimSpace(logs) == "" {
		return ""
	}

	lines := strings.Split(logs, "\n")
	var processedLines []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) > 1 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}' {
			if unpacked, ok := unpackJSONLine(trimmed); ok {
				processedLines = append(processedLines, unpacked...)
				continue
			}
		}
		processedLines = append(processedLines, line)
	}

	return strings.Join(processedLines, "\n")
}

// unpackJSONLine extracts error-relevant keys from a single JSON log line.
func unpackJSONLine(raw string) ([]string, bool) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return nil, false
	}

	var parts []string

	// Check common level or severity
	var level string
	for _, k := range []string{"level", "severity", "status", "log_level"} {
		if v, ok := obj[k].(string); ok {
			level = strings.ToUpper(v)
			break
		}
	}

	// Check common message keys
	var msg string
	for _, k := range []string{"message", "msg", "log", "text"} {
		if v, ok := obj[k].(string); ok && v != "" {
			msg = v
			break
		}
	}

	header := ""
	if level != "" {
		header = "[" + level + "] "
	}
	if msg != "" {
		header += msg
	}
	if header != "" {
		parts = append(parts, header)
	}

	// Check error or exception string/object
	for _, k := range []string{"error", "err", "exception", "cause", "reason"} {
		if v, ok := obj[k]; ok && v != nil {
			switch val := v.(type) {
			case string:
				if val != "" && val != msg {
					parts = append(parts, val)
				}
			case map[string]interface{}:
				if errBytes, err := json.Marshal(val); err == nil {
					parts = append(parts, string(errBytes))
				}
			}
		}
	}

	// Check stack trace keys
	for _, k := range []string{"stack_trace", "stacktrace", "stack", "traceback"} {
		if v, ok := obj[k].(string); ok && v != "" {
			parts = append(parts, strings.Split(v, "\n")...)
		}
	}

	if len(parts) == 0 {
		return nil, false
	}

	return parts, true
}
