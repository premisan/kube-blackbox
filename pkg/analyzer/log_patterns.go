package analyzer

import (
	"regexp"
	"strconv"
	"strings"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
)

type LogRule struct {
	Name              string
	Category          string // Application, Configuration, Dependency, Infrastructure
	RootCause         string
	Confidence        string // High, Medium, Low
	Regex             *regexp.Regexp
	SummaryTpl        string
	RecommendedAction string
	ExtractClass      func(match []string) string
	ExtractLocation   func(logs string) string
	ExtractCulprit    func(logs string) *observerv1alpha1.CulpritCode
}

var logRules = []LogRule{
	// ==================== Architecture & OS Execution ====================
	{
		Name:              "ExecFormatError",
		Category:          "Configuration",
		RootCause:         "ArchitectureMismatch",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:exec format error|cannot execute binary file: Exec format error)`),
		SummaryTpl:        "Binary CPU architecture mismatch (e.g. running amd64 binary on arm64 node, or vice versa)",
		RecommendedAction: "Rebuild the container image with multi-arch (buildx --platform linux/amd64,linux/arm64) to match the cluster node architecture.",
		ExtractClass:      func(m []string) string { return "ExecFormatError" },
	},
	{
		Name:              "EntrypointNotFound",
		Category:          "Configuration",
		RootCause:         "EntrypointScriptNotFound",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:/bin/sh:\s*(.+?):\s*not found|executable file not found in \$PATH|no such file or directory:\s*(.+))`),
		SummaryTpl:        "Container entrypoint or required binary not found: %s",
		RecommendedAction: "Verify file existence in Docker image or check glibc/musl compatibility (common in Alpine base images).",
		ExtractClass:      func(m []string) string { return "FileNotFound" },
	},

	// ==================== Java / JVM ====================
	{
		Name:              "JVMHeapOOM",
		Category:          "Application",
		RootCause:         "JVMHeapOOM",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`java\.lang\.OutOfMemoryError:\s*Java heap space`),
		SummaryTpl:        "JVM exhausted heap memory (java.lang.OutOfMemoryError: Java heap space)",
		RecommendedAction: "Increase JVM -Xmx heap limit, increase Pod memory limit, or profile memory leaks with heap dump.",
		ExtractClass:      func(m []string) string { return "OutOfMemoryError" },
		ExtractLocation:   extractJavaLocation,
		ExtractCulprit:    extractJavaCulprit,
	},
	{
		Name:              "JVMMetaspaceOOM",
		Category:          "Application",
		RootCause:         "JVMMetaspaceOOM",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`java\.lang\.OutOfMemoryError:\s*Metaspace`),
		SummaryTpl:        "JVM Metaspace memory exhausted",
		RecommendedAction: "Tune -XX:MaxMetaspaceSize or check for classloader leaks caused by dynamic proxies/frameworks.",
		ExtractClass:      func(m []string) string { return "MetaspaceOOM" },
	},
	{
		Name:              "JVMDirectMemoryOOM",
		Category:          "Application",
		RootCause:         "JVMDirectMemoryOOM",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`java\.lang\.OutOfMemoryError:\s*Direct buffer memory`),
		SummaryTpl:        "JVM Direct Buffer memory exhausted",
		RecommendedAction: "Check NIO / Netty bytebuf releases or adjust -XX:MaxDirectMemorySize.",
		ExtractClass:      func(m []string) string { return "DirectBufferOOM" },
	},
	{
		Name:              "JVMStackOverflow",
		Category:          "Application",
		RootCause:         "JVMStackOverflow",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`java\.lang\.StackOverflowError`),
		SummaryTpl:        "JVM call stack overflow caused by deep or infinite recursion",
		RecommendedAction: "Inspect recursion logic in the call stack or increase thread stack size (-Xss).",
		ExtractClass:      func(m []string) string { return "StackOverflowError" },
		ExtractLocation:   extractJavaLocation,
		ExtractCulprit:    extractJavaCulprit,
	},
	{
		Name:              "SpringBootStartupFailure",
		Category:          "Application",
		RootCause:         "SpringBootStartupFailure",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:ApplicationContextException|BeanCreationException|APPLICATION FAILED TO START)`),
		SummaryTpl:        "Spring Boot application context initialization failed",
		RecommendedAction: "Inspect Spring Boot configuration properties (application.yml) and missing bean dependencies.",
		ExtractClass:      func(m []string) string { return "BeanCreationException" },
		ExtractLocation:   extractJavaLocation,
		ExtractCulprit:    extractJavaCulprit,
	},

	// ==================== Python ====================
	{
		Name:              "PythonMemoryError",
		Category:          "Application",
		RootCause:         "PythonMemoryError",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?m)^MemoryError$`),
		SummaryTpl:        "Python process exhausted process memory limit (MemoryError)",
		RecommendedAction: "Optimize large dataframe/data loading into batches or increase pod memory limit.",
		ExtractClass:      func(m []string) string { return "MemoryError" },
	},
	{
		Name:              "PythonModuleNotFound",
		Category:          "Configuration",
		RootCause:         "PythonModuleNotFound",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?m)(?:ModuleNotFoundError:\s*No module named\s*['"](.+?)['"]|ImportError:\s*cannot import name\s*['"](.+?)['"])`),
		SummaryTpl:        "Python missing dependency: %s",
		RecommendedAction: "Add the missing package to requirements.txt and rebuild the Docker container.",
		ExtractClass:      func(m []string) string { return "ModuleNotFoundError" },
	},
	{
		Name:              "PythonTraceback",
		Category:          "Application",
		RootCause:         "PythonUnhandledException",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?m)Traceback \(most recent call last\):`),
		SummaryTpl:        "Unhandled Python exception caused application termination",
		RecommendedAction: "Inspect the Python exception traceback in the error snippet and wrap in try-except.",
		ExtractClass:      extractPythonExceptionClass,
		ExtractLocation:   extractPythonLocation,
		ExtractCulprit:    extractPythonCulprit,
	},

	// ==================== Node.js / JavaScript / TypeScript ====================
	{
		Name:              "NodeHeapOOM",
		Category:          "Application",
		RootCause:         "NodeHeapOOM",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:JavaScript heap out of memory|Ineffective mark-compacts near heap limit)`),
		SummaryTpl:        "Node.js V8 engine exhausted JavaScript heap memory",
		RecommendedAction: "Increase heap size via NODE_OPTIONS=\"--max-old-space-size=4096\" or check for memory leaks.",
		ExtractClass:      func(m []string) string { return "JavaScriptHeapOOM" },
	},
	{
		Name:              "NodeModuleNotFound",
		Category:          "Configuration",
		RootCause:         "NodeModuleNotFound",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:Cannot find module\s*['"](.+?)['"]|code:\s*['"]MODULE_NOT_FOUND['"])`),
		SummaryTpl:        "Node.js missing module dependency: %s",
		RecommendedAction: "Verify package.json dependencies and ensure npm/yarn install ran during image build.",
		ExtractClass:      func(m []string) string { return "ModuleNotFound" },
	},
	{
		Name:              "NodeUnhandledRejection",
		Category:          "Application",
		RootCause:         "NodeUnhandledPromiseRejection",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:UnhandledPromiseRejection|UnhandledPromiseRejectionWarning|uncaughtException)`),
		SummaryTpl:        "Node.js crashed due to uncaught promise rejection or unhandled exception",
		RecommendedAction: "Add .catch() to unhandled promises or wrap asynchronous calls in try/catch.",
		ExtractClass:      func(m []string) string { return "UnhandledPromiseRejection" },
		ExtractLocation:   extractNodeLocation,
		ExtractCulprit:    extractNodeCulprit,
	},

	// ==================== Go (Golang) ====================
	{
		Name:              "GoDeadlock",
		Category:          "Application",
		RootCause:         "GoDeadlock",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`fatal error:\s*all goroutines are asleep - deadlock!`),
		SummaryTpl:        "Go runtime detected all goroutines asleep (Deadlock)",
		RecommendedAction: "Check mutex lock/unlock sequences and channel send/receive synchronization logic.",
		ExtractClass:      func(m []string) string { return "Deadlock" },
		ExtractLocation:   extractGoLocation,
		ExtractCulprit:    extractGoCulprit,
	},
	{
		Name:              "GoConcurrentMapAccess",
		Category:          "Application",
		RootCause:         "GoConcurrentMapAccess",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`fatal error:\s*concurrent map (?:writes|read and map write)`),
		SummaryTpl:        "Go crash: concurrent read/write to standard map without synchronization",
		RecommendedAction: "Use sync.RWMutex to protect map access or replace with sync.Map.",
		ExtractClass:      func(m []string) string { return "ConcurrentMapAccess" },
		ExtractLocation:   extractGoLocation,
		ExtractCulprit:    extractGoCulprit,
	},
	{
		Name:              "GoPanic",
		Category:          "Application",
		RootCause:         "GoPanic",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?m)^panic:\s*(.+)$`),
		SummaryTpl:        "Go runtime panic: %s",
		RecommendedAction: "Inspect call stack for nil pointer dereference, slice bounds out of range, or unhandled errors.",
		ExtractClass:      func(m []string) string { return "Panic" },
		ExtractLocation:   extractGoLocation,
		ExtractCulprit:    extractGoCulprit,
	},

	// ==================== .NET / C# ====================
	{
		Name:              "DotNetNullReference",
		Category:          "Application",
		RootCause:         "DotNetNullReference",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)System\.NullReferenceException:\s*Object reference not set to an instance of an object`),
		SummaryTpl:        ".NET NullReferenceException: Object reference not set to an instance of an object",
		RecommendedAction: "Verify that object instances are initialized before accessing members or use C# null-conditional operator (?.).",
		ExtractClass:      func(m []string) string { return "NullReferenceException" },
		ExtractLocation:   extractDotNetLocation,
		ExtractCulprit:    extractDotNetCulprit,
	},
	{
		Name:              "DotNetOOM",
		Category:          "Application",
		RootCause:         "DotNetOOM",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)System\.OutOfMemoryException`),
		SummaryTpl:        ".NET runtime exhausted managed memory (System.OutOfMemoryException)",
		RecommendedAction: "Check Large Object Heap (LOH) allocations or increase container memory limits.",
		ExtractClass:      func(m []string) string { return "OutOfMemoryException" },
	},
	{
		Name:              "DotNetUnhandled",
		Category:          "Application",
		RootCause:         "DotNetUnhandledException",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)Unhandled exception\.\s*(System\.[a-zA-Z0-9_\.]+)`),
		SummaryTpl:        "Unhandled .NET exception: %s",
		RecommendedAction: "Inspect exception stack trace and add top-level try/catch or ASP.NET Core exception middleware.",
		ExtractClass:      func(m []string) string { return "DotNetException" },
		ExtractLocation:   extractDotNetLocation,
		ExtractCulprit:    extractDotNetCulprit,
	},

	// ==================== PHP ====================
	{
		Name:              "PHPMemoryExhausted",
		Category:          "Application",
		RootCause:         "PHPMemoryExhausted",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)Fatal error:\s*Allowed memory size of (\d+) bytes exhausted`),
		SummaryTpl:        "PHP memory limit exhausted: %s bytes",
		RecommendedAction: "Increase memory_limit in php.ini or refactor memory-intensive loops.",
		ExtractClass:      func(m []string) string { return "MemoryExhausted" },
		ExtractLocation:   extractPHPLocation,
		ExtractCulprit:    extractPHPCulprit,
	},
	{
		Name:              "PHPUncaughtError",
		Category:          "Application",
		RootCause:         "PHPUncaughtError",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)Fatal error:\s*Uncaught (?:Error|Exception):\s*(.+)`),
		SummaryTpl:        "PHP fatal uncaught error: %s",
		RecommendedAction: "Check PHP script error and implement global try-catch exception handling.",
		ExtractClass:      func(m []string) string { return "FatalError" },
		ExtractLocation:   extractPHPLocation,
		ExtractCulprit:    extractPHPCulprit,
	},

	// ==================== Ruby ====================
	{
		Name:              "RubyNoMemoryError",
		Category:          "Application",
		RootCause:         "RubyNoMemoryError",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?m)(?:NoMemoryError|failed to allocate memory)`),
		SummaryTpl:        "Ruby process exhausted available memory (NoMemoryError)",
		RecommendedAction: "Profile heap object allocation in Ruby/Rails and increase pod memory limits.",
		ExtractClass:      func(m []string) string { return "NoMemoryError" },
	},
	{
		Name:              "RubySystemStackError",
		Category:          "Application",
		RootCause:         "RubySystemStackError",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`SystemStackError:\s*stack level too deep`),
		SummaryTpl:        "Ruby call stack overflow (SystemStackError: stack level too deep)",
		RecommendedAction: "Inspect recursive methods or cyclic method calls in Rails models/controllers.",
		ExtractClass:      func(m []string) string { return "SystemStackError" },
	},

	// ==================== Rust ====================
	{
		Name:              "RustPanic",
		Category:          "Application",
		RootCause:         "RustPanic",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`thread\s*['"].*?['"]\s*panicked at\s*['"]?(.*?)['"]?,`),
		SummaryTpl:        "Rust thread panicked: %s",
		RecommendedAction: "Check unwrap()/expect() calls on None or Err variants in the referenced source location.",
		ExtractClass:      func(m []string) string { return "RustPanic" },
	},

	// ==================== Native Crash (C/C++, FFI) ====================
	{
		Name:              "SegmentationFault",
		Category:          "Application",
		RootCause:         "SegmentationFault",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:segmentation fault|SIGSEGV|signal 11)`),
		SummaryTpl:        "Process terminated due to segmentation fault (SIGSEGV)",
		RecommendedAction: "Inspect native C/C++ library dependencies, unsafe pointers, or corrupt shared objects (.so).",
		ExtractClass:      func(m []string) string { return "SIGSEGV" },
	},
	{
		Name:              "AbortedSignal",
		Category:          "Application",
		RootCause:         "NativeAbort",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:SIGABRT|aborted \(core dumped\)|assertion failed)`),
		SummaryTpl:        "Process triggered assertion failure or SIGABRT",
		RecommendedAction: "Check C-level assert statements or library initialization errors.",
		ExtractClass:      func(m []string) string { return "SIGABRT" },
	},

	// ==================== Web Proxy / Ingress (Nginx, Envoy) ====================
	{
		Name:              "NginxWorkerConnections",
		Category:          "Infrastructure",
		RootCause:         "NginxWorkerConnections",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)worker_connections are not enough`),
		SummaryTpl:        "Nginx exhausted worker connections limit under high concurrency load",
		RecommendedAction: "Increase worker_connections and worker_processes in nginx.conf or scale out replicas.",
		ExtractClass:      func(m []string) string { return "WorkerConnectionsExhausted" },
	},

	// ==================== Database & Cache ====================
	{
		Name:              "RedisOOM",
		Category:          "Application",
		RootCause:         "RedisOOM",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)OOM command not allowed when used memory > 'maxmemory'`),
		SummaryTpl:        "Redis reached maxmemory limit; write commands rejected with OOM",
		RecommendedAction: "Increase Redis maxmemory or configure eviction policy (e.g. maxmemory-policy allkeys-lru).",
		ExtractClass:      func(m []string) string { return "RedisOOM" },
	},
	{
		Name:              "DiskNoSpaceLeft",
		Category:          "Infrastructure",
		RootCause:         "DiskNoSpaceLeft",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:no space left on device|ENOSPC)`),
		SummaryTpl:        "Container local filesystem ran out of storage space (ENOSPC: No space left on device)",
		RecommendedAction: "Clean temporary files or increase pod ephemeral-storage requests/limits.",
		ExtractClass:      func(m []string) string { return "ENOSPC" },
	},

	// ==================== Network & Dependencies ====================
	{
		Name:              "AddressAlreadyInUse",
		Category:          "Dependency",
		RootCause:         "PortConflict",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:address already in use|bind:\s*address already in use|EADDRINUSE)`),
		SummaryTpl:        "Port binding conflict detected: %s",
		RecommendedAction: "Change the container listen port or verify no zombie process is occupying the port.",
		ExtractClass:      func(m []string) string { return "EADDRINUSE" },
	},
	{
		Name:              "DNSLookupFailed",
		Category:          "Dependency",
		RootCause:         "DNSLookupFailed",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)dial tcp:\s*lookup\s*([a-zA-Z0-9_\.-]+):\s*no such host`),
		SummaryTpl:        "DNS lookup failed for hostname: %s",
		RecommendedAction: "Check CoreDNS status, verify service name and cluster DNS configuration.",
		ExtractClass:      func(m []string) string { return "DNSNotFound" },
	},
	{
		Name:              "DBAuthFailed",
		Category:          "Configuration",
		RootCause:         "DatabaseAuthFailure",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:password authentication failed for user|Access denied for user\s*['"].*?['"]|AuthenticationFailed)`),
		SummaryTpl:        "Database connection authentication failed",
		RecommendedAction: "Verify database username, password secrets, and permissions for the connecting user.",
		ExtractClass:      func(m []string) string { return "AuthFailed" },
	},
	{
		Name:              "TLSValidationFailed",
		Category:          "Configuration",
		RootCause:         "TLSValidationFailed",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:certificate signed by unknown authority|SSL:\s*CERTIFICATE_VERIFY_FAILED|x509:\s*certificate)`),
		SummaryTpl:        "TLS certificate verification failed connecting to dependency",
		RecommendedAction: "Mount internal CA certificates or check certificate expiration dates.",
		ExtractClass:      func(m []string) string { return "TLSVerifyFailed" },
	},
	{
		Name:              "ConnectionRefused",
		Category:          "Dependency",
		RootCause:         "ConnectionRefused",
		Confidence:        "Medium",
		Regex:             regexp.MustCompile(`(?i)(?:connection refused|dial tcp.*?connect:\s*connection refused|ECONNREFUSED)`),
		SummaryTpl:        "Dependency service refused connection",
		RecommendedAction: "Check if upstream database, cache, or API service is ready and network policies allow traffic.",
		ExtractClass:      func(m []string) string { return "ECONNREFUSED" },
	},
	{
		Name:              "FatalErrorGeneral",
		Category:          "Application",
		RootCause:         "AppFatalError",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:fatal error:\s*(.+)|\[FATAL\]\s*(.+)|FATAL:\s*(.+))`),
		SummaryTpl:        "Fatal application error encountered: %s",
		RecommendedAction: "Inspect application configuration and initialize parameters in the log snippet.",
		ExtractClass:      func(m []string) string { return "FatalError" },
	},
}

type LogAnalysisResult struct {
	MatchedRule       *LogRule
	MatchedPattern    string
	Category          string
	ErrorClass        string
	ErrorLocation     string
	CulpritCode       *observerv1alpha1.CulpritCode
	Snippet           string
	Summary           string
	RecommendedAction string
}

// AnalyzeLogs searches previous container logs for known failure patterns.
func AnalyzeLogs(logs string) *LogAnalysisResult {
	if strings.TrimSpace(logs) == "" {
		return nil
	}

	// 1. Preprocess structured JSON logs if present
	processedLogs := PreprocessLogs(logs)

	lines := strings.Split(processedLogs, "\n")
	tailSnippet := extractTailSnippet(lines, 15)

	for _, rule := range logRules {
		if loc := rule.Regex.FindStringSubmatch(processedLogs); len(loc) > 0 {
			matched := loc[0]
			detail := matched
			for k := 1; k < len(loc); k++ {
				if loc[k] != "" {
					detail = strings.TrimSpace(loc[k])
					break
				}
			}

			summary := rule.SummaryTpl
			if strings.Contains(rule.SummaryTpl, "%s") {
				summary = strings.Replace(rule.SummaryTpl, "%s", truncateString(detail, 80), 1)
			}

			var errClass string
			if rule.ExtractClass != nil {
				errClass = rule.ExtractClass(loc)
			}

			var errLocation string
			if rule.ExtractLocation != nil {
				errLocation = rule.ExtractLocation(processedLogs)
			}

			var culprit *observerv1alpha1.CulpritCode
			if rule.ExtractCulprit != nil {
				culprit = rule.ExtractCulprit(processedLogs)
			}

			return &LogAnalysisResult{
				MatchedRule:       &rule,
				MatchedPattern:    rule.Name,
				Category:          rule.Category,
				ErrorClass:        errClass,
				ErrorLocation:     errLocation,
				CulpritCode:       culprit,
				Snippet:           tailSnippet,
				Summary:           summary,
				RecommendedAction: rule.RecommendedAction,
			}
		}
	}

	return &LogAnalysisResult{
		MatchedRule:       nil,
		MatchedPattern:    "",
		Category:          "Unknown",
		Snippet:           tailSnippet,
		Summary:           "",
		RecommendedAction: "",
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

// Regex helpers for locations
var (
	goLocRegex     = regexp.MustCompile(`(?m)^\t(.+?\.(?:go|s)):(\d+)`)
	pythonLocRegex = regexp.MustCompile(`File "([^"]+)", line (\d+)(?:, in (\w+))?`)
	javaLocRegex   = regexp.MustCompile(`at\s+([a-zA-Z0-9_\.$]+)\(([a-zA-Z0-9_\.]+\.java):(\d+)\)`)
	nodeLocRegex   = regexp.MustCompile(`at\s+(?:.+?\s+\()?([^()\s]+?\.(?:js|ts|mjs)):(\d+):(\d+)\)?`)
	dotNetLocRegex = regexp.MustCompile(`at\s+([^\(\n]+)\(.*?\) in (.+?\.(?:cs|fs)):line (\d+)`)
	phpLocRegex    = regexp.MustCompile(`in (.+?\.php) on line (\d+)`)
)

func extractGoLocation(logs string) string {
	matches := goLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) > 0 {
		raw := matches[0][1]
		line := matches[0][2]
		parts := strings.Split(raw, "/")
		fileName := parts[len(parts)-1]
		return fileName + ":" + line
	}
	return ""
}

func extractGoCulprit(logs string) *observerv1alpha1.CulpritCode {
	matches := goLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) == 0 {
		return nil
	}
	for _, m := range matches {
		filePath := m[1]
		lineStr := m[2]
		// Skip Go standard library runtime files
		if strings.Contains(filePath, "runtime/") || strings.Contains(filePath, "testing/") {
			continue
		}
		lineNum, _ := strconv.Atoi(lineStr)
		parts := strings.Split(filePath, "/")
		fileName := parts[len(parts)-1]
		return &observerv1alpha1.CulpritCode{
			Language: "Go",
			File:     fileName,
			Line:     lineNum,
		}
	}
	return nil
}

func extractPythonLocation(logs string) string {
	matches := pythonLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) > 0 {
		last := matches[len(matches)-1]
		parts := strings.Split(last[1], "/")
		fileName := parts[len(parts)-1]
		return fileName + ":" + last[2]
	}
	return ""
}

func extractPythonCulprit(logs string) *observerv1alpha1.CulpritCode {
	matches := pythonLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) == 0 {
		return nil
	}
	// Walk backwards to find the last user code frame before crash
	for i := len(matches) - 1; i >= 0; i-- {
		m := matches[i]
		filePath := m[1]
		// Skip python internal site-packages if possible
		if strings.Contains(filePath, "site-packages") || strings.Contains(filePath, "lib/python") {
			continue
		}
		lineNum, _ := strconv.Atoi(m[2])
		parts := strings.Split(filePath, "/")
		return &observerv1alpha1.CulpritCode{
			Language: "Python",
			File:     parts[len(parts)-1],
			Line:     lineNum,
			Function: m[3],
		}
	}
	// Fallback to last frame
	last := matches[len(matches)-1]
	lineNum, _ := strconv.Atoi(last[2])
	parts := strings.Split(last[1], "/")
	return &observerv1alpha1.CulpritCode{
		Language: "Python",
		File:     parts[len(parts)-1],
		Line:     lineNum,
		Function: last[3],
	}
}

func extractPythonExceptionClass(matches []string) string {
	return "PythonException"
}

func extractJavaLocation(logs string) string {
	matches := javaLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) > 0 {
		return matches[0][2] + ":" + matches[0][3]
	}
	return ""
}

func extractJavaCulprit(logs string) *observerv1alpha1.CulpritCode {
	matches := javaLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) == 0 {
		return nil
	}
	// Walk through stack to find user code (ignoring Spring/JDK internal calls)
	for _, m := range matches {
		fullPkg := m[1]
		fileName := m[2]
		lineStr := m[3]
		if strings.HasPrefix(fullPkg, "org.springframework.") ||
			strings.HasPrefix(fullPkg, "java.") ||
			strings.HasPrefix(fullPkg, "sun.") ||
			strings.HasPrefix(fullPkg, "jdk.") ||
			strings.HasPrefix(fullPkg, "org.apache.") {
			continue
		}
		lineNum, _ := strconv.Atoi(lineStr)
		return &observerv1alpha1.CulpritCode{
			Language:  "Java",
			Framework: "Spring",
			File:      fileName,
			Line:      lineNum,
			Function:  fullPkg,
		}
	}
	// Fallback to first line
	first := matches[0]
	lineNum, _ := strconv.Atoi(first[3])
	return &observerv1alpha1.CulpritCode{
		Language: "Java",
		File:     first[2],
		Line:     lineNum,
		Function: first[1],
	}
}

func extractNodeLocation(logs string) string {
	matches := nodeLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) > 0 {
		parts := strings.Split(matches[0][1], "/")
		return parts[len(parts)-1] + ":" + matches[0][2]
	}
	return ""
}

func extractNodeCulprit(logs string) *observerv1alpha1.CulpritCode {
	matches := nodeLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) == 0 {
		return nil
	}
	for _, m := range matches {
		filePath := m[1]
		if strings.Contains(filePath, "node_modules") {
			continue
		}
		lineNum, _ := strconv.Atoi(m[2])
		parts := strings.Split(filePath, "/")
		return &observerv1alpha1.CulpritCode{
			Language: "JavaScript/TypeScript",
			File:     parts[len(parts)-1],
			Line:     lineNum,
		}
	}
	return nil
}

func extractDotNetLocation(logs string) string {
	matches := dotNetLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) > 0 {
		parts := strings.Split(matches[0][2], "/")
		if len(parts) == 1 {
			parts = strings.Split(matches[0][2], "\\")
		}
		return parts[len(parts)-1] + ":" + matches[0][3]
	}
	return ""
}

func extractDotNetCulprit(logs string) *observerv1alpha1.CulpritCode {
	matches := dotNetLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) == 0 {
		return nil
	}
	first := matches[0]
	lineNum, _ := strconv.Atoi(first[3])
	parts := strings.Split(first[2], "/")
	if len(parts) == 1 {
		parts = strings.Split(first[2], "\\")
	}
	return &observerv1alpha1.CulpritCode{
		Language: ".NET/C#",
		File:     parts[len(parts)-1],
		Line:     lineNum,
		Function: strings.TrimSpace(first[1]),
	}
}

func extractPHPLocation(logs string) string {
	matches := phpLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) > 0 {
		parts := strings.Split(matches[0][1], "/")
		return parts[len(parts)-1] + ":" + matches[0][2]
	}
	return ""
}

func extractPHPCulprit(logs string) *observerv1alpha1.CulpritCode {
	matches := phpLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) == 0 {
		return nil
	}
	first := matches[0]
	lineNum, _ := strconv.Atoi(first[2])
	parts := strings.Split(first[1], "/")
	return &observerv1alpha1.CulpritCode{
		Language: "PHP",
		File:     parts[len(parts)-1],
		Line:     lineNum,
	}
}
