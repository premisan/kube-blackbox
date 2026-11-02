package knowledge

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
)

// UniversalCrashAnalysis represents the Sentry-grade diagnostic findings extracted
// directly from container log streams without relying on rigid pattern whitelists.
type UniversalCrashAnalysis struct {
	Language       string                         // Python, Java, Node.js, Go, PHP, Rust, C/C++
	ErrorClass     string                         // KeyError, NullPointerException, TypeError, etc.
	ErrorMessage   string                         // Raw error message
	CulpritCode    *observerv1alpha1.CulpritCode  // In-App user file, line, and function
	ErrorLocation  string                         // file.py:42
	Fingerprint    string                         // Sentry-style issue hash: lang:class:file:line:func
	FocusedSnippet string                         // Focused 15-20 line error window excluding shutdown noise
	Breadcrumbs    []string                       // Pre-crash 3-5 log events
	CausedByChain  []string                       // Unwrapped root cause cascade
}

var (
	// Python Traceback & Frame Regexes
	pyTracebackStartRegex = regexp.MustCompile(`(?m)^Traceback \(most recent call last\):`)
	pyUniversalFrameRegex = regexp.MustCompile(`(?m)^\s*File "([^"]+)", line (\d+)(?:, in ([^\n\r]+))?`)
	pyUniversalExcRegex   = regexp.MustCompile(`(?m)^([A-Za-z_][A-Za-z0-9_\.]*(?:Error|Exception|Warning|Interrupt|FatalError|Exit))(?::\s*(.*))?$`)

	// Java StackTrace & Caused-by Regexes
	javaUniversalTopExcRegex   = regexp.MustCompile(`(?m)^([a-zA-Z0-9_\.\$]+(?:Exception|Error|Throwable))(?::\s*(.*))?$`)
	javaUniversalCausedByRegex = regexp.MustCompile(`(?m)^Caused by:\s*([a-zA-Z0-9_\.\$]+(?:Exception|Error|Throwable))(?::\s*(.*))?$`)
	javaUniversalFrameRegex    = regexp.MustCompile(`^\s*at\s+([a-zA-Z0-9_\.$]+)\.([a-zA-Z0-9_$<>]+\b)\((?:([a-zA-Z0-9_\.]+\.java):(\d+)|Native Method|Unknown Source)\)`)

	// Node.js V8 StackTrace Regexes
	nodeUniversalFrameRegex = regexp.MustCompile(`^\s*at\s+(?:async\s+)?(?:([^\s(]+)\s+\((?:file:\/\/)?([^:]+):(\d+):(\d+)\)|(?:file:\/\/)?([^:]+):(\d+):(\d+))`)
	nodeUniversalExcRegex   = regexp.MustCompile(`(?m)^([a-zA-Z0-9_\.]*(?:Error|Exception|TypeError|ReferenceError|SyntaxError|RangeError|URIError|EvalError))(?::\s*(.*))?$`)

	// Go Runtime Panic Regexes
	goPanicRegex      = regexp.MustCompile(`(?m)^panic:\s*(.*)$`)
	goGoroutineRegex  = regexp.MustCompile(`(?m)^goroutine \d+ \[[^\]]+\]:`)
	goStackFrameRegex = regexp.MustCompile(`^\s*([^\s\(]+)\([^\)]*\)\r?\n\s+([^\s:]+):(\d+)(?:\s+\+0x[0-9a-f]+)?`)

	// Common shutdown noise keywords to trim from bottom of error window
	shutdownNoisePatterns = []string{
		"Worker exiting (pid:",
		"Shutting down: Master",
		"Closed all listening sockets",
		"Stopping AsyncLoader",
		"Stopped cgroup current memory usage",
		"Shutting down storages",
		"Shutdown completed",
		"Graceful shutdown complete",
		"Terminating process",
	}
)

// AnalyzeUniversalCrash inspects raw container logs and extracts Sentry-grade crash diagnostics
// even if no specific hardcoded log pattern was previously registered.
func AnalyzeUniversalCrash(logs string) *UniversalCrashAnalysis {
	if strings.TrimSpace(logs) == "" {
		return nil
	}

	// 1. Try Python Traceback
	if strings.Contains(logs, "Traceback (most recent call last):") || strings.Contains(logs, "Fatal Python error:") {
		if analysis := parsePythonUniversalTraceback(logs); analysis != nil {
			return analysis
		}
	}

	// 2. Try Java / Kotlin StackTrace
	if (strings.Contains(logs, "\tat ") || strings.Contains(logs, "    at ")) &&
		(strings.Contains(logs, "Exception") || strings.Contains(logs, "Error:") || strings.Contains(logs, "Throwable")) {
		if analysis := parseJavaUniversalStackTrace(logs); analysis != nil {
			return analysis
		}
	}

	// 3. Try Node.js / TypeScript V8 StackTrace
	if strings.Contains(logs, "    at ") || strings.Contains(logs, "  at ") || strings.Contains(logs, "UnhandledPromiseRejection") {
		if analysis := parseNodeUniversalStackTrace(logs); analysis != nil {
			return analysis
		}
	}

	// 4. Try Go Runtime Panic
	if strings.Contains(logs, "panic:") && (strings.Contains(logs, "goroutine ") || strings.Contains(logs, ".go:")) {
		if analysis := parseGoUniversalPanic(logs); analysis != nil {
			return analysis
		}
	}

	// 5. Try Semantic Generic Error (e.g. Database connection failure, unhandled exceptions)
	if analysis := parseGenericSemanticError(logs); analysis != nil {
		return analysis
	}

	return nil
}

// ==================== Python Traceback Parser ====================
func parsePythonUniversalTraceback(logs string) *UniversalCrashAnalysis {
	excMatches := pyUniversalExcRegex.FindAllStringSubmatch(logs, -1)
	if len(excMatches) == 0 {
		return nil
	}

	// The last exception is typically the final raised error
	lastExc := excMatches[len(excMatches)-1]
	excClass := lastExc[1]
	excMsg := ""
	if len(lastExc) > 2 {
		excMsg = strings.TrimSpace(lastExc[2])
	}

	analysis := &UniversalCrashAnalysis{
		Language:     "Python",
		ErrorClass:   excClass,
		ErrorMessage: excMsg,
	}

	// Detect Chained Exceptions ("During handling of the above exception, another exception occurred:")
	if strings.Contains(logs, "During handling of the above exception") || strings.Contains(logs, "direct cause of the following exception") {
		for _, m := range excMatches {
			analysis.CausedByChain = append(analysis.CausedByChain, m[1])
		}
	}

	// Parse all frames and select the deepest In-App (user code) frame
	frameMatches := pyUniversalFrameRegex.FindAllStringSubmatch(logs, -1)
	for i := len(frameMatches) - 1; i >= 0; i-- {
		m := frameMatches[i]
		filePath := m[1]
		lineNum, _ := strconv.Atoi(m[2])
		fn := ""
		if len(m) > 3 {
			fn = strings.TrimSpace(m[3])
		}

		isUser := !strings.Contains(filePath, "site-packages") &&
			!strings.Contains(filePath, "lib/python") &&
			!strings.Contains(filePath, ".venv") &&
			!strings.Contains(filePath, "virtualenv") &&
			!strings.Contains(filePath, "venv/") &&
			!strings.Contains(filePath, "<frozen ")

		parts := strings.Split(filePath, "/")
		fileName := parts[len(parts)-1]

		if isUser && analysis.CulpritCode == nil {
			analysis.CulpritCode = &observerv1alpha1.CulpritCode{
				Language: "Python",
				File:     fileName,
				Line:     lineNum,
				Function: fn,
			}
			analysis.ErrorLocation = fmt.Sprintf("%s:%d", fileName, lineNum)
			break
		}
	}

	// Fallback to deepest library frame if no user code found
	if analysis.CulpritCode == nil && len(frameMatches) > 0 {
		last := frameMatches[len(frameMatches)-1]
		lineNum, _ := strconv.Atoi(last[2])
		fn := ""
		if len(last) > 3 {
			fn = strings.TrimSpace(last[3])
		}
		parts := strings.Split(last[1], "/")
		analysis.CulpritCode = &observerv1alpha1.CulpritCode{
			Language: "Python",
			File:     parts[len(parts)-1],
			Line:     lineNum,
			Function: fn,
		}
		analysis.ErrorLocation = fmt.Sprintf("%s:%d", parts[len(parts)-1], lineNum)
	}

	// Generate Sentry-style Fingerprint
	analysis.Fingerprint = generateFingerprint("py", analysis.ErrorClass, analysis.CulpritCode)

	// Extract focused error snippet & breadcrumbs
	analysis.FocusedSnippet, analysis.Breadcrumbs = extractSmartErrorWindow(logs, "Traceback (most recent call last):")

	return analysis
}

// ==================== Java / Kotlin StackTrace Parser ====================
func parseJavaUniversalStackTrace(logs string) *UniversalCrashAnalysis {
	// Parse Caused-by Chain (Root cause unwrapping)
	causedMatches := javaUniversalCausedByRegex.FindAllStringSubmatch(logs, -1)
	var rootExcClass string
	var rootExcMsg string
	var chain []string

	topMatches := javaUniversalTopExcRegex.FindAllStringSubmatch(logs, -1)
	if len(topMatches) > 0 {
		rootExcClass = topMatches[0][1]
		if len(topMatches[0]) > 2 {
			rootExcMsg = strings.TrimSpace(topMatches[0][2])
		}
		chain = append(chain, rootExcClass)
	}

	if len(causedMatches) > 0 {
		for _, cm := range causedMatches {
			chain = append(chain, cm[1])
		}
		// Sentry principle: The innermost Caused-by is the true root cause
		innermost := causedMatches[len(causedMatches)-1]
		rootExcClass = innermost[1]
		if len(innermost) > 2 {
			rootExcMsg = strings.TrimSpace(innermost[2])
		}
	}

	if rootExcClass == "" {
		return nil
	}

	analysis := &UniversalCrashAnalysis{
		Language:      "Java",
		ErrorClass:    rootExcClass,
		ErrorMessage:  rootExcMsg,
		CausedByChain: chain,
	}

	// Parse stack frames to locate In-App user code
	lines := strings.Split(logs, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if m := javaUniversalFrameRegex.FindStringSubmatch(trimmed); len(m) >= 3 {
			fullClass := m[1]
			method := m[2]
			file := ""
			lineNum := 0
			if len(m) >= 5 && m[3] != "" {
				file = m[3]
				lineNum, _ = strconv.Atoi(m[4])
			}

			if isJavaUserCode(fullClass) && analysis.CulpritCode == nil {
				analysis.CulpritCode = &observerv1alpha1.CulpritCode{
					Language: "Java",
					File:     file,
					Line:     lineNum,
					Function: fullClass + "." + method,
				}
				if file != "" && lineNum > 0 {
					analysis.ErrorLocation = fmt.Sprintf("%s:%d", file, lineNum)
				}
				break
			}
		}
	}

	analysis.Fingerprint = generateFingerprint("java", analysis.ErrorClass, analysis.CulpritCode)
	analysis.FocusedSnippet, analysis.Breadcrumbs = extractSmartErrorWindow(logs, rootExcClass)

	return analysis
}

// ==================== Node.js / TypeScript StackTrace Parser ====================
func parseNodeUniversalStackTrace(logs string) *UniversalCrashAnalysis {
	excMatches := nodeUniversalExcRegex.FindAllStringSubmatch(logs, -1)
	excClass := "Error"
	excMsg := ""
	if len(excMatches) > 0 {
		excClass = excMatches[0][1]
		if len(excMatches[0]) > 2 {
			excMsg = strings.TrimSpace(excMatches[0][2])
		}
	} else if strings.Contains(logs, "UnhandledPromiseRejection") {
		excClass = "UnhandledPromiseRejection"
	}

	analysis := &UniversalCrashAnalysis{
		Language:     "JavaScript/TypeScript",
		ErrorClass:   excClass,
		ErrorMessage: excMsg,
	}

	lines := strings.Split(logs, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if m := nodeUniversalFrameRegex.FindStringSubmatch(trimmed); len(m) >= 5 {
			fn := m[1]
			file := m[2]
			lineStr := m[3]
			if file == "" && len(m) >= 8 {
				file = m[5]
				lineStr = m[6]
			}
			lineNum, _ := strconv.Atoi(lineStr)

			isUser := !strings.Contains(file, "node_modules") &&
				!strings.Contains(file, "node:internal") &&
				!strings.Contains(file, "internal/process") &&
				!strings.Contains(file, "internal/modules")

			if isUser && analysis.CulpritCode == nil && file != "" && lineNum > 0 {
				parts := strings.Split(file, "/")
				fileName := parts[len(parts)-1]
				analysis.CulpritCode = &observerv1alpha1.CulpritCode{
					Language: "JavaScript/TypeScript",
					File:     fileName,
					Line:     lineNum,
					Function: fn,
				}
				analysis.ErrorLocation = fmt.Sprintf("%s:%d", fileName, lineNum)
				break
			}
		}
	}

	analysis.Fingerprint = generateFingerprint("node", analysis.ErrorClass, analysis.CulpritCode)
	analysis.FocusedSnippet, analysis.Breadcrumbs = extractSmartErrorWindow(logs, excClass)

	return analysis
}

// ==================== Go Runtime Panic Parser ====================
func parseGoUniversalPanic(logs string) *UniversalCrashAnalysis {
	panicMatches := goPanicRegex.FindStringSubmatch(logs)
	panicMsg := "runtime panic"
	if len(panicMatches) >= 2 {
		panicMsg = strings.TrimSpace(panicMatches[1])
	}

	analysis := &UniversalCrashAnalysis{
		Language:     "Go",
		ErrorClass:   "Panic",
		ErrorMessage: panicMsg,
	}

	// Locate culprit file and line from Go stack frames
	lines := strings.Split(logs, "\n")
	for i := 0; i < len(lines)-1; i++ {
		line := strings.TrimSpace(lines[i])
		nextLine := strings.TrimSpace(lines[i+1])

		if strings.HasPrefix(nextLine, "/") && strings.Contains(nextLine, ".go:") {
			parts := strings.Split(nextLine, ":")
			if len(parts) >= 2 {
				fileParts := strings.Split(parts[0], "/")
				fileName := fileParts[len(fileParts)-1]
				subParts := strings.Split(parts[1], " ")
				lineNum, _ := strconv.Atoi(subParts[0])

				isUser := !strings.Contains(parts[0], "/runtime/") &&
					!strings.Contains(parts[0], "/net/http") &&
					!strings.Contains(parts[0], "/testing/")

				if isUser && analysis.CulpritCode == nil && lineNum > 0 {
					analysis.CulpritCode = &observerv1alpha1.CulpritCode{
						Language: "Go",
						File:     fileName,
						Line:     lineNum,
						Function: line,
					}
					analysis.ErrorLocation = fmt.Sprintf("%s:%d", fileName, lineNum)
					break
				}
			}
		}
	}

	analysis.Fingerprint = generateFingerprint("go", analysis.ErrorClass, analysis.CulpritCode)
	analysis.FocusedSnippet, analysis.Breadcrumbs = extractSmartErrorWindow(logs, "panic:")

	return analysis
}

// ==================== Generic Semantic Error Parser ====================
func parseGenericSemanticError(logs string) *UniversalCrashAnalysis {
	lowerLogs := strings.ToLower(logs)

	// Check common network / database connection failures
	if strings.Contains(lowerLogs, "connection refused") || strings.Contains(lowerLogs, "dial tcp") {
		return &UniversalCrashAnalysis{
			Language:       "System",
			ErrorClass:     "ConnectionRefused",
			ErrorMessage:   "TCP connection refused or dial timeout to target endpoint",
			FocusedSnippet: extractTailSnippetLines(logs, 15),
		}
	}
	if strings.Contains(lowerLogs, "connection reset by peer") {
		return &UniversalCrashAnalysis{
			Language:       "System",
			ErrorClass:     "ConnectionResetByPeer",
			ErrorMessage:   "Upstream peer abruptly closed TCP connection",
			FocusedSnippet: extractTailSnippetLines(logs, 15),
		}
	}
	if strings.Contains(lowerLogs, "no route to host") || strings.Contains(lowerLogs, "i/o timeout") {
		return &UniversalCrashAnalysis{
			Language:       "System",
			ErrorClass:     "NetworkTimeout",
			ErrorMessage:   "Network routing failure or socket I/O timeout",
			FocusedSnippet: extractTailSnippetLines(logs, 15),
		}
	}

	return nil
}

// ==================== Smart Error Windowing & Sentry Helpers ====================

// extractSmartErrorWindow finds the error anchor in logs and extracts the 15-20 line
// window surrounding the actual crash, discarding trailing shutdown noise.
func extractSmartErrorWindow(logs, anchorKeyword string) (string, []string) {
	lines := strings.Split(logs, "\n")
	if len(lines) <= 20 {
		return strings.Join(lines, "\n"), extractPreCrashBreadcrumbs(lines, len(lines)-1)
	}

	// Find the last occurrence of anchor keyword
	anchorIdx := -1
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], anchorKeyword) {
			anchorIdx = i
			break
		}
	}

	if anchorIdx == -1 {
		// Fallback to tail
		start := len(lines) - 18
		if start < 0 {
			start = 0
		}
		return strings.Join(lines[start:], "\n"), extractPreCrashBreadcrumbs(lines, len(lines)-1)
	}

	// Find start index (breadcrumbs before error)
	startIdx := anchorIdx - 4
	if startIdx < 0 {
		startIdx = 0
	}

	// Find end index (trim trailing shutdown noise)
	endIdx := anchorIdx + 14
	if endIdx >= len(lines) {
		endIdx = len(lines) - 1
	}

	// Trim trailing shutdown messages if present after error
	for j := anchorIdx + 1; j <= endIdx; j++ {
		isNoise := false
		for _, noise := range shutdownNoisePatterns {
			if strings.Contains(lines[j], noise) {
				isNoise = true
				break
			}
		}
		if isNoise && j > anchorIdx+4 {
			endIdx = j - 1
			break
		}
	}

	snippet := strings.Join(lines[startIdx:endIdx+1], "\n")
	breadcrumbs := extractPreCrashBreadcrumbs(lines, anchorIdx)
	return snippet, breadcrumbs
}

func extractPreCrashBreadcrumbs(lines []string, anchorIdx int) []string {
	var breadcrumbs []string
	start := anchorIdx - 5
	if start < 0 {
		start = 0
	}
	for i := start; i < anchorIdx && i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed != "" {
			breadcrumbs = append(breadcrumbs, trimmed)
		}
	}
	return breadcrumbs
}

func extractTailSnippetLines(logs string, n int) string {
	lines := strings.Split(logs, "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}

func generateFingerprint(lang, errorClass string, culprit *observerv1alpha1.CulpritCode) string {
	raw := fmt.Sprintf("%s:%s", lang, errorClass)
	if culprit != nil {
		raw = fmt.Sprintf("%s:%s:%s:%d:%s", lang, errorClass, culprit.File, culprit.Line, culprit.Function)
	}
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h[:8])
}
