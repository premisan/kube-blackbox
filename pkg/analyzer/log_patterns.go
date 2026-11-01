package analyzer

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
	"github.com/premisan/kube-blackbox/pkg/analyzer/knowledge"
)

type LogRule struct {
	Name                 string
	Category             string // Application, Configuration, Dependency, Infrastructure
	RootCause            string
	Confidence           string // High, Medium, Low
	Regex                *regexp.Regexp
	SummaryTpl           string
	RecommendedAction    string
	ExtractClass         func(match []string) string
	ExtractClassFromLogs func(logs string) string
	ExtractLocation      func(logs string) string
	ExtractCulprit       func(logs string) *observerv1alpha1.CulpritCode
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
	{
		Name:              "PermissionDeniedLog",
		Category:          "Configuration",
		RootCause:         "PermissionDenied",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:permission denied|EACCES: permission denied)`),
		SummaryTpl:        "Operation or execution failed due to permission denied (EACCES)",
		RecommendedAction: "Check securityContext, container runAsUser/runAsGroup, and filesystem volume mount permissions.",
		ExtractClass:      func(m []string) string { return "PermissionDenied" },
	},

	// ==================== Java / JVM / Spring ====================
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
		Name:              "JVMThreadExhaustion",
		Category:          "Application",
		RootCause:         "JVMThreadExhaustion",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`java\.lang\.OutOfMemoryError:\s*unable to create (?:new )?native thread`),
		SummaryTpl:        "JVM unable to create native OS threads (PID or thread limit exhausted)",
		RecommendedAction: "Review thread pools, decrease thread stack size (-Xss), or increase node/cgroup pids.max limit.",
		ExtractClass:      func(m []string) string { return "ThreadExhaustion" },
	},
	{
		Name:              "JVMGCOverheadOOM",
		Category:          "Application",
		RootCause:         "JVMGCOverheadOOM",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`java\.lang\.OutOfMemoryError:\s*GC overhead limit exceeded`),
		SummaryTpl:        "JVM GC overhead limit exceeded (GC spent >98%% CPU freeing <2%% memory)",
		RecommendedAction: "Profile heap memory allocation churn, expand -Xmx, or optimize object creation in tight loops.",
		ExtractClass:      func(m []string) string { return "GCOverheadOOM" },
		ExtractLocation:   extractJavaLocation,
		ExtractCulprit:    extractJavaCulprit,
	},
	{
		Name:              "JVMCompressedClassSpaceOOM",
		Category:          "Application",
		RootCause:         "JVMCompressedClassSpaceOOM",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`java\.lang\.OutOfMemoryError:\s*Compressed class space`),
		SummaryTpl:        "JVM Compressed Class Space exhausted",
		RecommendedAction: "Increase -XX:CompressedClassSpaceSize or inspect excessive dynamic bytecode generation.",
		ExtractClass:      func(m []string) string { return "CompressedClassSpaceOOM" },
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
		Name:              "JVMNullPointerException",
		Category:          "Application",
		RootCause:         "JVMNullPointer",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:java\.lang\.NullPointerException|\bNullPointerException\b)`),
		SummaryTpl:        "JVM NullPointerException thrown during execution",
		RecommendedAction: "Check null check validations or uninitialized dependencies at the referenced line.",
		ExtractClass:      func(m []string) string { return "NullPointerException" },
		ExtractLocation:   extractJavaLocation,
		ExtractCulprit:    extractJavaCulprit,
	},
	{
		Name:              "JVMClassNotFound",
		Category:          "Configuration",
		RootCause:         "JVMClassNotFound",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:ClassNotFoundException|NoClassDefFoundError):\s*([a-zA-Z0-9_\.$]+)`),
		SummaryTpl:        "JVM class or dependency not found on classpath: %s",
		RecommendedAction: "Verify jar dependencies, classpath arguments, and shading/packaging configuration.",
		ExtractClass:      func(m []string) string { return "ClassNotFound" },
	},
	{
		Name:              "SpringPortInUse",
		Category:          "Dependency",
		RootCause:         "SpringPortInUse",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:PortInUseException|Web server failed to start\. Port \d+ was already in use)`),
		SummaryTpl:        "Spring Boot embedded web server port already bound by another process",
		RecommendedAction: "Configure server.port in application.yml or check for duplicate processes on the same host/pod network.",
		ExtractClass:      func(m []string) string { return "PortInUse" },
	},
	{
		Name:              "SpringHikariPoolExhaustion",
		Category:          "Dependency",
		RootCause:         "SpringHikariPoolExhaustion",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:HikariPool-.*?Connection is not available, request timed out after|ConnectionPoolTimeoutException)`),
		SummaryTpl:        "HikariCP database connection pool exhausted under concurrent traffic",
		RecommendedAction: "Increase spring.datasource.hikari.maximum-pool-size or optimize long-running SQL transactions.",
		ExtractClass:      func(m []string) string { return "ConnectionPoolExhausted" },
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
	{
		Name:              "JVMSegfaultCrash",
		Category:          "Application",
		RootCause:         "JVMSegfaultCrash",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:# A fatal error has been detected by the Java Runtime Environment|# Problematic frame:|hs_err_pid\d+\.log)`),
		SummaryTpl:        "JVM crashed in native code (SIGSEGV in JNI, JVM C++ internals, or native driver)",
		RecommendedAction: "Inspect hs_err_pid log for problematic native frame or update JNI library / JVM distribution.",
		ExtractClass:      func(m []string) string { return "JVMNativeCrash" },
	},
	{
		Name:              "KafkaBrokerUnavailable",
		Category:          "Dependency",
		RootCause:         "KafkaBrokerUnavailable",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:org\.apache\.kafka\.common\.errors\.TimeoutException:\s*Failed to update metadata|LeaderNotAvailableException|DisconnectException)`),
		SummaryTpl:        "Kafka broker unreachable or cluster metadata update timed out",
		RecommendedAction: "Check Kafka bootstrap servers, VPC routing, broker health, and topic partition leaders.",
		ExtractClass:      func(m []string) string { return "KafkaUnavailable" },
	},
	{
		Name:              "ElasticsearchConnectTimeout",
		Category:          "Dependency",
		RootCause:         "ElasticsearchConnectTimeout",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:ConnectTimeoutException.*?Connect to .*? failed|ElasticsearchStatusException)`),
		SummaryTpl:        "Elasticsearch cluster connection timed out or returned error status",
		RecommendedAction: "Verify Elasticsearch endpoint connectivity, cluster load, and client socket timeout settings.",
		ExtractClass:      func(m []string) string { return "ElasticsearchTimeout" },
	},

	// ==================== Go / Golang ====================
	{
		Name:              "GoDeadlock",
		Category:          "Application",
		RootCause:         "GoDeadlock",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`fatal error:\s*all goroutines are asleep - deadlock!`),
		SummaryTpl:        "Go runtime detected fatal deadlock (all goroutines asleep)",
		RecommendedAction: "Review channel read/write synchronization and mutex lock/unlock order across goroutines.",
		ExtractClass:      func(m []string) string { return "GoDeadlock" },
		ExtractLocation:   extractGoLocation,
		ExtractCulprit:    extractGoCulprit,
	},
	{
		Name:              "GoConcurrentMapAccess",
		Category:          "Application",
		RootCause:         "GoConcurrentMapAccess",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`fatal error:\s*concurrent map (?:read and map write|writes)`),
		SummaryTpl:        "Go fatal concurrent map read/write access",
		RecommendedAction: "Protect map access with sync.RWMutex or migrate to sync.Map for concurrent operations.",
		ExtractClass:      func(m []string) string { return "ConcurrentMapAccess" },
		ExtractLocation:   extractGoLocation,
		ExtractCulprit:    extractGoCulprit,
	},
	{
		Name:              "GoNilPointerDereference",
		Category:          "Application",
		RootCause:         "GoNilPointerDereference",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`panic:\s*runtime error:\s*invalid memory address or nil pointer dereference`),
		SummaryTpl:        "Go runtime panic: nil pointer dereference",
		RecommendedAction: "Add nil checks before dereferencing struct pointers or interface values at the indicated location.",
		ExtractClass:      func(m []string) string { return "NilPointerDereference" },
		ExtractLocation:   extractGoLocation,
		ExtractCulprit:    extractGoCulprit,
	},
	{
		Name:              "GoIndexOutOfRange",
		Category:          "Application",
		RootCause:         "GoIndexOutOfRange",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`panic:\s*runtime error:\s*index out of range`),
		SummaryTpl:        "Go runtime panic: slice/array index out of range",
		RecommendedAction: "Verify slice length boundaries before accessing elements by index.",
		ExtractClass:      func(m []string) string { return "IndexOutOfRange" },
		ExtractLocation:   extractGoLocation,
		ExtractCulprit:    extractGoCulprit,
	},
	{
		Name:              "GoSliceBoundsOutOfRange",
		Category:          "Application",
		RootCause:         "GoSliceBoundsOutOfRange",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`panic:\s*runtime error:\s*slice bounds out of range`),
		SummaryTpl:        "Go runtime panic: slice sub-slice bounds exceed capacity/length",
		RecommendedAction: "Validate low/high slice indices against len() and cap() before slicing.",
		ExtractClass:      func(m []string) string { return "SliceBoundsOutOfRange" },
		ExtractLocation:   extractGoLocation,
		ExtractCulprit:    extractGoCulprit,
	},
	{
		Name:              "GoRuntimeOOM",
		Category:          "Application",
		RootCause:         "GoRuntimeOOM",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`fatal error:\s*out of memory|runtime:\s*cannot allocate memory`),
		SummaryTpl:        "Go runtime memory allocator failure (heap exhaustion)",
		RecommendedAction: "Profile heap profiles (pprof) or increase Pod memory limit.",
		ExtractClass:      func(m []string) string { return "GoRuntimeOOM" },
		ExtractLocation:   extractGoLocation,
		ExtractCulprit:    extractGoCulprit,
	},
	{
		Name:              "GoStackOverflow",
		Category:          "Application",
		RootCause:         "GoStackOverflow",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`fatal error:\s*stack overflow`),
		SummaryTpl:        "Go goroutine stack overflow caused by infinite or uncontrolled recursion",
		RecommendedAction: "Check recursive functions and terminate conditions in the stack trace.",
		ExtractClass:      func(m []string) string { return "StackOverflow" },
		ExtractLocation:   extractGoLocation,
		ExtractCulprit:    extractGoCulprit,
	},
	{
		Name:              "GoPortInUse",
		Category:          "Dependency",
		RootCause:         "GoPortInUse",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`listen tcp\s*:.*:\s*bind:\s*address already in use`),
		SummaryTpl:        "Go HTTP/TCP server failed to bind: address already in use",
		RecommendedAction: "Change listener port in server config or ensure previous instance exited completely.",
		ExtractClass:      func(m []string) string { return "PortAlreadyInUse" },
	},
	{
		Name:              "GoPanic",
		Category:          "Application",
		RootCause:         "AppPanic",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`panic:\s*(.+)`),
		SummaryTpl:        "Go unhandled application panic: %s",
		RecommendedAction: "Add recover() middleware or fix the root cause in the culprit stack frame.",
		ExtractClass:      func(m []string) string { return "GoPanic" },
		ExtractLocation:   extractGoLocation,
		ExtractCulprit:    extractGoCulprit,
	},

	// ==================== Python ====================
	{
		Name:              "PythonMemoryError",
		Category:          "Application",
		RootCause:         "PythonMemoryError",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)\bMemoryError\b`),
		SummaryTpl:        "Python process exhausted process memory limit (MemoryError)",
		RecommendedAction: "Optimize memory usage (generators, streaming) or increase Pod memory limit.",
		ExtractClass:      func(m []string) string { return "MemoryError" },
		ExtractLocation:   extractPythonLocation,
		ExtractCulprit:    extractPythonCulprit,
	},
	{
		Name:              "PythonModuleNotFound",
		Category:          "Configuration",
		RootCause:         "PythonModuleNotFound",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:ModuleNotFoundError:\s*No module named\s*['"](.+?)['"]|ImportError:\s*cannot import name\s*['"](.+?)['"])`),
		SummaryTpl:        "Missing required Python module or package: %s",
		RecommendedAction: "Add the missing package to requirements.txt and re-install inside Dockerfile.",
		ExtractClass:      func(m []string) string { return "ModuleNotFoundError" },
	},
	{
		Name:              "PythonRecursionError",
		Category:          "Application",
		RootCause:         "PythonRecursionError",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`RecursionError:\s*maximum recursion depth exceeded`),
		SummaryTpl:        "Python call stack depth limit exceeded (maximum recursion depth)",
		RecommendedAction: "Fix base cases in recursive algorithms or rewrite logic iteratively.",
		ExtractClass:      func(m []string) string { return "RecursionError" },
		ExtractLocation:   extractPythonLocation,
		ExtractCulprit:    extractPythonCulprit,
	},
	{
		Name:              "PythonSyntaxError",
		Category:          "Application",
		RootCause:         "PythonSyntaxError",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:SyntaxError:\s*invalid syntax|IndentationError:)`),
		SummaryTpl:        "Python script syntax or indentation error",
		RecommendedAction: "Check Python source file formatting, indentation spaces, or Python version syntax compatibility.",
		ExtractClass:      func(m []string) string { return "SyntaxError" },
		ExtractLocation:   extractPythonLocation,
		ExtractCulprit:    extractPythonCulprit,
	},
	{
		Name:              "PythonAttributeError",
		Category:          "Application",
		RootCause:         "PythonAttributeError",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`AttributeError:\s*'NoneType' object has no attribute\s*['"](.+?)['"]`),
		SummaryTpl:        "Python AttributeError: 'NoneType' object has no attribute '%s'",
		RecommendedAction: "Ensure function or database query returned a non-None value before accessing attributes.",
		ExtractClass:      func(m []string) string { return "AttributeError" },
		ExtractLocation:   extractPythonLocation,
		ExtractCulprit:    extractPythonCulprit,
	},
	{
		Name:              "PythonKeyOrIndexError",
		Category:          "Application",
		RootCause:         "PythonKeyOrIndexError",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:KeyError:\s*(.+)|IndexError:\s*list index out of range)`),
		SummaryTpl:        "Python dictionary KeyError or list IndexError",
		RecommendedAction: "Use dict.get(key, default) or verify list length before indexing.",
		ExtractClass:      func(m []string) string { return "KeyOrIndexError" },
		ExtractLocation:   extractPythonLocation,
		ExtractCulprit:    extractPythonCulprit,
	},
	{
		Name:              "PythonWorkerTimeout",
		Category:          "Application",
		RootCause:         "PythonWorkerTimeout",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:\[CRITICAL\]\s*WORKER TIMEOUT|Worker .*? was sent SIGKILL)`),
		SummaryTpl:        "Gunicorn/Uvicorn worker process timed out and was killed by arbiter",
		RecommendedAction: "Increase Gunicorn --timeout setting or profile slow database queries / external HTTP calls blocking the event loop.",
		ExtractClass:      func(m []string) string { return "WorkerTimeout" },
	},
	{
		Name:              "PythonDjangoDBConnRefused",
		Category:          "Dependency",
		RootCause:         "PythonDjangoDBConnRefused",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:django\.db\.utils\.OperationalError:\s*could not connect to server|psycopg2\.OperationalError:\s*could not connect)`),
		SummaryTpl:        "Django / Psycopg2 failed to establish connection to PostgreSQL server",
		RecommendedAction: "Check PostgreSQL database host, port, credentials, and network connectivity.",
		ExtractClass:      func(m []string) string { return "DBConnectionRefused" },
	},
	{
		Name:              "PythonSQLAlchemyPoolExhausted",
		Category:          "Dependency",
		RootCause:         "PythonSQLAlchemyPoolExhausted",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)sqlalchemy\.exc\.TimeoutError:\s*QueuePool limit of size .*? overflow .*? reached`),
		SummaryTpl:        "SQLAlchemy QueuePool connection pool exhausted",
		RecommendedAction: "Increase pool_size/max_overflow or ensure database sessions are properly closed with context managers.",
		ExtractClass:      func(m []string) string { return "PoolExhausted" },
	},
	{
		Name:              "PyTorchCUDA_OOM",
		Category:          "Infrastructure",
		RootCause:         "PyTorchCUDA_OOM",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)RuntimeError:\s*CUDA out of memory`),
		SummaryTpl:        "PyTorch CUDA GPU VRAM memory exhausted",
		RecommendedAction: "Reduce batch size, use torch.cuda.empty_cache(), or migrate to a node with higher GPU VRAM.",
		ExtractClass:      func(m []string) string { return "CUDA_OOM" },
	},
	{
		Name:                 "PythonTraceback",
		Category:             "Application",
		RootCause:            "PythonUnhandledException",
		Confidence:           "High",
		Regex:                regexp.MustCompile(`Traceback \(most recent call last\):`),
		SummaryTpl:           "Python unhandled exception: %s",
		RecommendedAction:    "Inspect traceback location and add try/except error handling or validate input data.",
		ExtractClass:         func(m []string) string { return "PythonException" },
		ExtractClassFromLogs: extractPythonExceptionClass,
		ExtractLocation:      extractPythonLocation,
		ExtractCulprit:       extractPythonCulprit,
	},

	// ==================== Node.js / TypeScript ====================
	{
		Name:              "NodeHeapOOM",
		Category:          "Application",
		RootCause:         "NodeHeapOOM",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:JavaScript heap out of memory|Allocation failed - JavaScript heap out of memory)`),
		SummaryTpl:        "Node.js V8 JavaScript heap memory limit exhausted",
		RecommendedAction: "Increase heap memory via NODE_OPTIONS=\"--max-old-space-size=4096\" or profile memory leaks.",
		ExtractClass:      func(m []string) string { return "JavaScriptHeapOOM" },
	},
	{
		Name:              "NodeCallStackExceeded",
		Category:          "Application",
		RootCause:         "NodeCallStackExceeded",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`RangeError:\s*Maximum call stack size exceeded`),
		SummaryTpl:        "Node.js call stack size exceeded (infinite recursion)",
		RecommendedAction: "Inspect recursive calls in the stack trace and ensure exit conditions are met.",
		ExtractClass:      func(m []string) string { return "RangeError" },
		ExtractLocation:   extractNodeLocation,
		ExtractCulprit:    extractNodeCulprit,
	},
	{
		Name:              "NodeTypeError",
		Category:          "Application",
		RootCause:         "NodeTypeError",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)TypeError:\s*(?:Cannot read propert(?:y|ies) of undefined|Cannot read propert(?:y|ies) of null)`),
		SummaryTpl:        "Node.js TypeError: Cannot read property of undefined or null",
		RecommendedAction: "Use optional chaining (?.) or validate object presence before property access.",
		ExtractClass:      func(m []string) string { return "TypeError" },
		ExtractLocation:   extractNodeLocation,
		ExtractCulprit:    extractNodeCulprit,
	},
	{
		Name:              "NodeModuleNotFound",
		Category:          "Configuration",
		RootCause:         "NodeModuleNotFound",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`Error:\s*Cannot find module\s*['"](.+?)['"]`),
		SummaryTpl:        "Missing Node.js module dependency: %s",
		RecommendedAction: "Run 'npm install' or 'yarn install' and ensure package.json contains all dependencies in production.",
		ExtractClass:      func(m []string) string { return "ModuleNotFound" },
	},
	{
		Name:              "NodePortInUse",
		Category:          "Dependency",
		RootCause:         "NodePortInUse",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`Error:\s*listen EADDRINUSE:\s*address already in use`),
		SummaryTpl:        "Node.js server port collision (EADDRINUSE)",
		RecommendedAction: "Change PORT environment variable or terminate competing process.",
		ExtractClass:      func(m []string) string { return "EADDRINUSE" },
	},
	{
		Name:              "NodePrismaInitFailed",
		Category:          "Dependency",
		RootCause:         "NodePrismaInitFailed",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)PrismaClientInitializationError:\s*Can't reach database server`),
		SummaryTpl:        "Prisma client initialization failed: unreachable database server",
		RecommendedAction: "Verify DATABASE_URL environment variable, database server availability, and network egress rules.",
		ExtractClass:      func(m []string) string { return "PrismaConnectionError" },
	},
	{
		Name:              "NodeMongooseTimeout",
		Category:          "Dependency",
		RootCause:         "NodeMongooseTimeout",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)MongooseServerSelectionError:\s*Could not connect to any servers`),
		SummaryTpl:        "Mongoose MongoDB replica set connection timeout",
		RecommendedAction: "Check MongoDB connection URI string, replica set names, and network access credentials.",
		ExtractClass:      func(m []string) string { return "MongooseTimeout" },
	},
	{
		Name:              "NodeUnhandledRejection",
		Category:          "Application",
		RootCause:         "NodeUnhandledRejection",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:UnhandledPromiseRejection|UnhandledPromiseRejectionWarning)`),
		SummaryTpl:        "Node.js unhandled asynchronous Promise rejection crash",
		RecommendedAction: "Attach .catch() handler or await in try/catch block for async promises.",
		ExtractClass:      func(m []string) string { return "UnhandledPromiseRejection" },
		ExtractLocation:   extractNodeLocation,
		ExtractCulprit:    extractNodeCulprit,
	},

	// ==================== Rust ====================
	{
		Name:              "RustUnwrapNone",
		Category:          "Application",
		RootCause:         "RustUnwrapNone",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`thread\s*['"].*?['"]\s*panicked at\s*['"]?called .*?Option::unwrap.*? on a .*?None.*? value`),
		SummaryTpl:        "Rust panic: Option::unwrap() called on a None value",
		RecommendedAction: "Handle None cases with match or if let instead of calling .unwrap().",
		ExtractClass:      func(m []string) string { return "UnwrapNone" },
		ExtractLocation:   extractRustLocation,
		ExtractCulprit:    extractRustCulprit,
	},
	{
		Name:              "RustUnwrapErr",
		Category:          "Application",
		RootCause:         "RustUnwrapErr",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`thread\s*['"].*?['"]\s*panicked at\s*['"]?called .*?Result::unwrap.*? on an .*?Err.*? value`),
		SummaryTpl:        "Rust panic: Result::unwrap() called on an Err value",
		RecommendedAction: "Propagate errors with '?' operator or handle Err variant gracefully.",
		ExtractClass:      func(m []string) string { return "UnwrapErr" },
		ExtractLocation:   extractRustLocation,
		ExtractCulprit:    extractRustCulprit,
	},
	{
		Name:              "RustAllocFailed",
		Category:          "Application",
		RootCause:         "RustAllocFailed",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`fatal runtime error:\s*memory allocation failed`),
		SummaryTpl:        "Rust global allocator failed to allocate memory",
		RecommendedAction: "Increase container memory limits or optimize large vector allocations.",
		ExtractClass:      func(m []string) string { return "AllocFailed" },
	},
	{
		Name:              "RustPanic",
		Category:          "Application",
		RootCause:         "RustPanic",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`thread\s*['"].*?['"]\s*panicked at\s*['"]?(.*?)['"]?,`),
		SummaryTpl:        "Rust thread panicked: %s",
		RecommendedAction: "Check unwrap()/expect() calls on None or Err variants in the referenced source location.",
		ExtractClass:      func(m []string) string { return "RustPanic" },
		ExtractLocation:   extractRustLocation,
		ExtractCulprit:    extractRustCulprit,
	},

	// ==================== .NET / C# ====================
	{
		Name:              "DotNetNullReference",
		Category:          "Application",
		RootCause:         "DotNetNullReference",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`System\.NullReferenceException:\s*Object reference not set to an instance of an object`),
		SummaryTpl:        ".NET NullReferenceException: Object reference not set to an instance of an object",
		RecommendedAction: "Use null-conditional operators (?.) or enable C# nullable reference types (<Nullable>enable</Nullable>).",
		ExtractClass:      func(m []string) string { return "NullReferenceException" },
		ExtractLocation:   extractDotNetLocation,
		ExtractCulprit:    extractDotNetCulprit,
	},
	{
		Name:              "DotNetOOM",
		Category:          "Application",
		RootCause:         "DotNetOOM",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`System\.OutOfMemoryException`),
		SummaryTpl:        ".NET runtime OutOfMemoryException",
		RecommendedAction: "Check large object heap (LOH) allocations or increase container memory limit.",
		ExtractClass:      func(m []string) string { return "OutOfMemoryException" },
	},
	{
		Name:              "DotNetConnectionPoolExhausted",
		Category:          "Dependency",
		RootCause:         "DotNetConnectionPoolExhausted",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)Timeout expired\. The timeout period elapsed prior to obtaining a connection from the pool`),
		SummaryTpl:        ".NET ADO.NET database connection pool exhausted",
		RecommendedAction: "Increase 'Max Pool Size' in connection string and verify all SqlConnection objects are disposed in 'using' blocks.",
		ExtractClass:      func(m []string) string { return "ConnectionPoolExhausted" },
	},
	{
		Name:              "DotNetPortInUse",
		Category:          "Dependency",
		RootCause:         "DotNetPortInUse",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)SocketException.*?Address already in use`),
		SummaryTpl:        ".NET Kestrel web server port binding conflict",
		RecommendedAction: "Change ASPNETCORE_URLS environment variable to an unused port.",
		ExtractClass:      func(m []string) string { return "PortInUse" },
	},
	{
		Name:              "DotNetAssemblyNotFound",
		Category:          "Configuration",
		RootCause:         "DotNetAssemblyNotFound",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)FileNotFoundException.*?Could not load file or assembly`),
		SummaryTpl:        ".NET Assembly or DLL dependency not found",
		RecommendedAction: "Ensure all referenced NuGet packages and DLLs are published in the Docker output directory.",
		ExtractClass:      func(m []string) string { return "AssemblyNotFound" },
	},
	{
		Name:              "DotNetStackOverflow",
		Category:          "Application",
		RootCause:         "DotNetStackOverflow",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)System\.StackOverflowException`),
		SummaryTpl:        ".NET CLR call stack overflow exception",
		RecommendedAction: "Inspect recursive calls in the stack trace and ensure exit conditions are met.",
		ExtractClass:      func(m []string) string { return "StackOverflowException" },
	},
	{
		Name:              "DotNetUnhandled",
		Category:          "Application",
		RootCause:         "DotNetUnhandledException",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`Unhandled exception\.\s*([a-zA-Z0-9_\.]+):\s*(.+)`),
		SummaryTpl:        ".NET unhandled exception crash: %s",
		RecommendedAction: "Inspect exception stack trace and add exception filter middleware.",
		ExtractClass:      func(m []string) string { return "DotNetException" },
		ExtractLocation:   extractDotNetLocation,
		ExtractCulprit:    extractDotNetCulprit,
	},

	// ==================== PHP & Ruby ====================
	{
		Name:              "PHPMemoryExhausted",
		Category:          "Application",
		RootCause:         "PHPMemoryExhausted",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`Fatal error:\s*Allowed memory size of (\d+) bytes exhausted`),
		SummaryTpl:        "PHP memory limit exhausted (%s bytes)",
		RecommendedAction: "Increase memory_limit in php.ini or optimize memory in large loop iterations.",
		ExtractClass:      func(m []string) string { return "MemoryExhausted" },
		ExtractLocation:   extractPHPLocation,
		ExtractCulprit:    extractPHPCulprit,
	},
	{
		Name:              "PHPExecutionTimeout",
		Category:          "Application",
		RootCause:         "PHPExecutionTimeout",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`Fatal error:\s*Maximum execution time of (\d+) seconds exceeded`),
		SummaryTpl:        "PHP max execution time exceeded (%s seconds)",
		RecommendedAction: "Increase max_execution_time in php.ini or optimize slow external network calls.",
		ExtractClass:      func(m []string) string { return "ExecutionTimeout" },
		ExtractLocation:   extractPHPLocation,
		ExtractCulprit:    extractPHPCulprit,
	},
	{
		Name:              "PHPCallOnNull",
		Category:          "Application",
		RootCause:         "PHPCallOnNull",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`Fatal error:\s*Uncaught Error:\s*Call to a member function .*? on null`),
		SummaryTpl:        "PHP fatal error: Call to a member function on null",
		RecommendedAction: "Validate variable is not null before method invocation.",
		ExtractClass:      func(m []string) string { return "CallOnNull" },
		ExtractLocation:   extractPHPLocation,
		ExtractCulprit:    extractPHPCulprit,
	},
	{
		Name:              "PHPUncaughtError",
		Category:          "Application",
		RootCause:         "PHPUncaughtError",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`Fatal error:\s*Uncaught\s*(.+?):\s*(.+)`),
		SummaryTpl:        "PHP fatal uncaught error: %s",
		RecommendedAction: "Wrap in try/catch block or register global error handler in index.php.",
		ExtractClass:      func(m []string) string { return "PHPError" },
		ExtractLocation:   extractPHPLocation,
		ExtractCulprit:    extractPHPCulprit,
	},
	{
		Name:              "RubyNoMemoryError",
		Category:          "Application",
		RootCause:         "RubyNoMemoryError",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`NoMemoryError:\s*failed to allocate memory`),
		SummaryTpl:        "Ruby process failed to allocate memory (NoMemoryError)",
		RecommendedAction: "Tune Jemalloc / Malloc memory allocator or increase container memory limit.",
		ExtractClass:      func(m []string) string { return "NoMemoryError" },
	},
	{
		Name:              "RubySystemStackError",
		Category:          "Application",
		RootCause:         "RubySystemStackError",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`SystemStackError:\s*stack level too deep`),
		SummaryTpl:        "Ruby stack level too deep (infinite recursion)",
		RecommendedAction: "Inspect recursion conditions or recursive ActiveRecord callbacks.",
		ExtractClass:      func(m []string) string { return "SystemStackError" },
	},
	{
		Name:              "RubyActiveRecordPoolExhausted",
		Category:          "Dependency",
		RootCause:         "RubyActiveRecordPoolExhausted",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)ActiveRecord::ConnectionTimeoutError:\s*could not obtain a connection from the pool`),
		SummaryTpl:        "Ruby on Rails ActiveRecord database connection pool exhausted",
		RecommendedAction: "Increase pool size in config/database.yml to match Puma max threads.",
		ExtractClass:      func(m []string) string { return "ConnectionTimeoutError" },
	},

	// ==================== Databases & Messaging ====================
	{
		Name:              "PostgresMaxConnections",
		Category:          "Dependency",
		RootCause:         "PostgresMaxConnections",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:FATAL:\s*remaining connection slots are reserved|FATAL:\s*sorry, too many clients already)`),
		SummaryTpl:        "PostgreSQL maximum client connections exceeded",
		RecommendedAction: "Deploy PgBouncer connection pooler or increase max_connections in postgresql.conf.",
		ExtractClass:      func(m []string) string { return "PostgresMaxConn" },
	},
	{
		Name:              "PostgresDeadlock",
		Category:          "Application",
		RootCause:         "PostgresDeadlock",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)ERROR:\s*deadlock detected`),
		SummaryTpl:        "PostgreSQL database transaction deadlock detected",
		RecommendedAction: "Ensure transactions acquire row/table locks in identical order.",
		ExtractClass:      func(m []string) string { return "DeadlockDetected" },
	},
	{
		Name:              "MySQLTooManyConnections",
		Category:          "Dependency",
		RootCause:         "MySQLTooManyConnections",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)ERROR 1040\s*\(HY000\):\s*Too many connections`),
		SummaryTpl:        "MySQL server connection limit reached (ERROR 1040)",
		RecommendedAction: "Increase max_connections in my.cnf or configure ProxySQL.",
		ExtractClass:      func(m []string) string { return "MySQLTooManyConnections" },
	},
	{
		Name:              "MySQLDeadlock",
		Category:          "Application",
		RootCause:         "MySQLDeadlock",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)ERROR 1213\s*\(40001\):\s*Deadlock found when trying to get lock`),
		SummaryTpl:        "MySQL InnoDB deadlock detected during concurrent transaction execution",
		RecommendedAction: "Retry transaction on deadlock error (1213) or index queried columns to avoid gap locks.",
		ExtractClass:      func(m []string) string { return "MySQLDeadlock" },
	},
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
		Name:              "RedisReadOnlyReplica",
		Category:          "Configuration",
		RootCause:         "RedisReadOnlyReplica",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)READONLY You can't write against a read only replica`),
		SummaryTpl:        "Write attempted against a Redis read-only replica instance",
		RecommendedAction: "Point write traffic to primary master endpoint or check Redis Sentinel/Cluster failover state.",
		ExtractClass:      func(m []string) string { return "RedisReadOnly" },
	},
	{
		Name:              "MongoServerSelectionTimeout",
		Category:          "Dependency",
		RootCause:         "MongoServerSelectionTimeout",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)MongoServerSelectionError:\s*Server selection timed out after`),
		SummaryTpl:        "MongoDB server selection timed out (cluster topology unreachable)",
		RecommendedAction: "Verify MongoDB Atlas network peering / IP access list or mongod container health.",
		ExtractClass:      func(m []string) string { return "MongoSelectionTimeout" },
	},
	{
		Name:              "RabbitMQChannelPreconditionFailed",
		Category:          "Application",
		RootCause:         "RabbitMQChannelPreconditionFailed",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)connection closed:\s*PRECONDITION_FAILED`),
		SummaryTpl:        "RabbitMQ channel closed: PRECONDITION_FAILED (queue parameter mismatch)",
		RecommendedAction: "Ensure queue durability, auto-delete, and x-arguments match between producer and consumer declarations.",
		ExtractClass:      func(m []string) string { return "PreconditionFailed" },
	},

	// ==================== Web Proxy / Ingress / Service Mesh ====================
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
	{
		Name:              "NginxBadGatewayUpstream",
		Category:          "Dependency",
		RootCause:         "NginxBadGatewayUpstream",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:502 Bad Gateway|connect\(\) failed \(111:\s*Connection refused\)\s*while connecting to upstream)`),
		SummaryTpl:        "Nginx 502 Bad Gateway: upstream application backend refused connection",
		RecommendedAction: "Check upstream service readiness, backend container port, and health check endpoints.",
		ExtractClass:      func(m []string) string { return "BadGatewayUpstream" },
	},
	{
		Name:              "NginxUpstreamTimedOut",
		Category:          "Dependency",
		RootCause:         "NginxUpstreamTimedOut",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:504 Gateway Time-out|upstream timed out \(110:\s*Connection timed out\))`),
		SummaryTpl:        "Nginx 504 Gateway Timeout: upstream application did not reply within proxy_read_timeout",
		RecommendedAction: "Increase proxy_read_timeout in nginx.conf or profile backend slow response times.",
		ExtractClass:      func(m []string) string { return "GatewayTimeout" },
	},
	{
		Name:              "EnvoyNoHealthyUpstream",
		Category:          "Dependency",
		RootCause:         "EnvoyNoHealthyUpstream",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:no healthy upstream|cluster_not_found|upstream connect error or disconnect/reset before headers)`),
		SummaryTpl:        "Envoy / Istio proxy found no healthy upstream backend endpoints",
		RecommendedAction: "Verify destination service pods are running, passing readiness probes, and Istio ServiceEntry/VirtualService rules.",
		ExtractClass:      func(m []string) string { return "NoHealthyUpstream" },
	},

	// ==================== Storage, OS & Native Crash ====================
	{
		Name:              "DiskNoSpaceLeft",
		Category:          "Infrastructure",
		RootCause:         "DiskNoSpaceLeft",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:no space left on device|ENOSPC|write error: No space left on device)`),
		SummaryTpl:        "Container local filesystem ran out of storage space (ENOSPC: No space left on device)",
		RecommendedAction: "Clean temporary files or increase pod ephemeral-storage requests/limits.",
		ExtractClass:      func(m []string) string { return "ENOSPC" },
	},
	{
		Name:              "FileDescriptorExhaustion",
		Category:          "Infrastructure",
		RootCause:         "FileDescriptorExhaustion",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:too many open files|EMFILE|ENFILE|SocketException:\s*Too many open files)`),
		SummaryTpl:        "System or container file descriptor limit exhausted (too many open files)",
		RecommendedAction: "Check file/socket descriptor leaks in application or increase ulimit / nofile settings in container.",
		ExtractClass:      func(m []string) string { return "EMFILE" },
	},
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
	{
		Name:              "BusError",
		Category:          "Application",
		RootCause:         "BusError",
		Confidence:        "High",
		Regex:             regexp.MustCompile(`(?i)(?:Bus error \(core dumped\)|SIGBUS|signal 7)`),
		SummaryTpl:        "Process crashed due to Bus Error (SIGBUS / unaligned memory access)",
		RecommendedAction: "Check memory-mapped files (mmap) or unaligned memory access in native code.",
		ExtractClass:      func(m []string) string { return "SIGBUS" },
	},

	// ==================== Network & Core Dependencies ====================
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
		Regex:             regexp.MustCompile(`(?i)(?:dial tcp:\s*lookup\s*([a-zA-Z0-9_\.-]+):\s*no such host|Temporary failure in name resolution|getaddrinfo ENOTFOUND\s*([a-zA-Z0-9_\.-]+))`),
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

var (
	domainRulesIndex map[string][]*LogRule
	allIndexedRules  []*LogRule
)

func init() {
	// Bridge embedded signatures from knowledge catalog into active log rules
	for _, sig := range knowledge.EmbeddedSignatures {
		s := sig
		r := LogRule{
			Name:              s.ID,
			Category:          s.Category,
			RootCause:         s.RootCause,
			Confidence:        s.Confidence,
			Regex:             s.Pattern,
			SummaryTpl:        s.SummaryEn,
			RecommendedAction: s.ActionEn,
			ExtractClass:      func(m []string) string { return s.ErrorClass },
		}
		if s.Domain == "cpp" {
			r.ExtractLocation = extractCppLocation
			r.ExtractCulprit = extractCppCulprit
		} else if s.Domain == "jvm" {
			r.ExtractLocation = extractJavaLocation
			r.ExtractCulprit = extractJavaCulprit
		} else if s.Domain == "python" {
			r.ExtractLocation = extractPythonLocation
			r.ExtractCulprit = extractPythonCulprit
		} else if s.Domain == "node" {
			r.ExtractLocation = extractNodeLocation
			r.ExtractCulprit = extractNodeCulprit
		}
		logRules = append(logRules, r)
	}

	// Build indexed domain mapping for hierarchical two-tier matching
	domainRulesIndex = make(map[string][]*LogRule)
	allIndexedRules = make([]*LogRule, len(logRules))
	for i := range logRules {
		r := &logRules[i]
		allIndexedRules[i] = r
		dom := classifyRuleDomain(r.Name)
		domainRulesIndex[dom] = append(domainRulesIndex[dom], r)
	}
}

func classifyRuleDomain(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "jvm") || strings.HasPrefix(lower, "spring") || strings.HasPrefix(lower, "kafka") || strings.HasPrefix(lower, "elastic"):
		return "jvm"
	case strings.HasPrefix(lower, "go"):
		return "go"
	case strings.HasPrefix(lower, "python") || strings.HasPrefix(lower, "pytorch"):
		return "python"
	case strings.HasPrefix(lower, "node"):
		return "node"
	case strings.HasPrefix(lower, "dotnet"):
		return "dotnet"
	case strings.HasPrefix(lower, "rust"):
		return "rust"
	case strings.HasPrefix(lower, "native") || strings.Contains(lower, "segfault") || strings.Contains(lower, "buserror") || strings.Contains(lower, "aborted"):
		return "cpp"
	case strings.HasPrefix(lower, "php") || strings.HasPrefix(lower, "ruby"):
		return "php_ruby"
	case strings.HasPrefix(lower, "postgres") || strings.HasPrefix(lower, "mysql") || strings.HasPrefix(lower, "redis") || strings.HasPrefix(lower, "mongo") || strings.HasPrefix(lower, "rabbit"):
		return "database"
	case strings.HasPrefix(lower, "nginx") || strings.HasPrefix(lower, "envoy"):
		return "web_proxy"
	case strings.HasPrefix(lower, "disk") || strings.HasPrefix(lower, "storage") || strings.HasPrefix(lower, "filedescriptor"):
		return "storage"
	case strings.HasPrefix(lower, "network") || strings.Contains(lower, "address") || strings.Contains(lower, "connection") || strings.Contains(lower, "dns"):
		return "network"
	default:
		return "general"
	}
}

func fastDetectDomains(logs string) []string {
	var domains []string
	lower := strings.ToLower(logs)

	if strings.Contains(lower, "java") || strings.Contains(lower, "outofmemoryerror") || strings.Contains(lower, "exception in thread") || strings.Contains(lower, "\tat ") || strings.Contains(lower, "spring") || strings.Contains(lower, "hikaripool") || strings.Contains(lower, "hs_err") {
		domains = append(domains, "jvm")
	}
	if strings.Contains(lower, "panic:") || strings.Contains(lower, "goroutine ") || strings.Contains(lower, "fatal error: concurrent map") || strings.Contains(lower, "all goroutines are asleep") {
		domains = append(domains, "go")
	}
	if strings.Contains(lower, "traceback (most recent call last)") || strings.Contains(lower, "file \"") || strings.Contains(lower, "fatal python error") || strings.Contains(lower, "faulthandler") {
		domains = append(domains, "python")
	}
	if strings.Contains(lower, "node_modules") || strings.Contains(lower, "typeerror") || strings.Contains(lower, "unhandledpromiserejection") || strings.Contains(lower, "javascript heap out of memory") {
		domains = append(domains, "node")
	}
	if strings.Contains(lower, "system.") || strings.Contains(lower, "nullreferenceexception") || strings.Contains(lower, "stackoverflowexception") {
		domains = append(domains, "dotnet")
	}
	if strings.Contains(lower, "panicked at") || strings.Contains(lower, "called `result::unwrap()`") || strings.Contains(lower, "called `option::unwrap()`") {
		domains = append(domains, "rust")
	}
	if strings.Contains(lower, "malloc():") || strings.Contains(lower, "double free") || strings.Contains(lower, "stack smashing") || strings.Contains(lower, "segmentation fault") || strings.Contains(lower, "sigsegv") || strings.Contains(lower, "sigbus") || strings.Contains(lower, "sigabrt") {
		domains = append(domains, "cpp")
	}
	if strings.Contains(lower, "read-only file system") || strings.Contains(lower, "erofs") || strings.Contains(lower, "too many open files") || strings.Contains(lower, "no space left on device") {
		domains = append(domains, "storage")
	}
	if strings.Contains(lower, "connection refused") || strings.Contains(lower, "address already in use") || strings.Contains(lower, "temporary failure in name resolution") || strings.Contains(lower, "econnrefused") {
		domains = append(domains, "network")
	}
	if strings.Contains(lower, "worker_connections") || strings.Contains(lower, "502 bad gateway") || strings.Contains(lower, "504 gateway") || strings.Contains(lower, "no healthy upstream") {
		domains = append(domains, "web_proxy")
	}
	if strings.Contains(lower, "max_connections") || strings.Contains(lower, "deadlock found") || strings.Contains(lower, "oom command not allowed") {
		domains = append(domains, "database")
	}

	return domains
}

func matchLogRule(rule *LogRule, processedLogs, tailSnippet string) *LogAnalysisResult {
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
			detailToInsert := truncateString(detail, 80)
			if rule.Name == "PythonTraceback" {
				if excDetail := extractPythonExceptionDetail(processedLogs); excDetail != "" {
					detailToInsert = truncateString(excDetail, 80)
				}
			}
			summary = strings.Replace(rule.SummaryTpl, "%s", detailToInsert, 1)
		}

		var errClass string
		if rule.ExtractClassFromLogs != nil {
			errClass = rule.ExtractClassFromLogs(processedLogs)
		} else if rule.ExtractClass != nil {
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
			MatchedRule:       rule,
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
	return nil
}

// AnalyzeLogs searches previous container logs for known failure patterns using hierarchical two-tier pre-filtering.
func AnalyzeLogs(logs string) *LogAnalysisResult {
	if strings.TrimSpace(logs) == "" {
		return nil
	}

	// 1. Preprocess structured JSON logs if present
	processedLogs := PreprocessLogs(logs)

	lines := strings.Split(processedLogs, "\n")
	tailSnippet := extractTailSnippet(lines, 15)

	// 2. Hierarchical fast pre-filtering: check candidate domains first
	detectedDomains := fastDetectDomains(processedLogs)
	checkedRules := make(map[*LogRule]bool)

	for _, dom := range detectedDomains {
		if rules, exists := domainRulesIndex[dom]; exists {
			for _, rule := range rules {
				checkedRules[rule] = true
				if res := matchLogRule(rule, processedLogs, tailSnippet); res != nil {
					return enrichWithDeepAnalysis(res, processedLogs, tailSnippet)
				}
			}
		}
	}

	// 3. Fallback scan: check remaining rules
	for _, rule := range allIndexedRules {
		if checkedRules[rule] {
			continue
		}
		if res := matchLogRule(rule, processedLogs, tailSnippet); res != nil {
			return enrichWithDeepAnalysis(res, processedLogs, tailSnippet)
		}
	}

	fallbackRes := &LogAnalysisResult{
		MatchedRule:       nil,
		MatchedPattern:    "",
		Category:          "Unknown",
		Snippet:           tailSnippet,
		Summary:           "",
		RecommendedAction: "",
	}
	return enrichWithDeepAnalysis(fallbackRes, processedLogs, tailSnippet)
}

func enrichWithDeepAnalysis(res *LogAnalysisResult, processedLogs string, tailSnippet string) *LogAnalysisResult {
	// 1. Python Deep Analysis
	if strings.Contains(processedLogs, "Traceback (most recent call last):") || strings.Contains(processedLogs, "Fatal Python error:") {
		pyDeep := knowledge.AnalyzePythonDeepCrash(processedLogs)
		if pyDeep != nil {
			if res == nil || res.MatchedRule == nil {
				res = &LogAnalysisResult{
					MatchedRule: &LogRule{
						Name:              "PythonDeepTraceback",
						Category:          "Application",
						RootCause:         "PythonUnhandledException",
						Confidence:        "High",
						RecommendedAction: "Inspect Python traceback and add error handling.",
					},
					MatchedPattern: "PythonDeepTraceback",
					Category:       "Application",
					Snippet:        tailSnippet,
				}
			}
			if pyDeep.IsChained && pyDeep.InitialCauseClass != "" {
				res.ErrorClass = fmt.Sprintf("%s (Chained from %s)", pyDeep.ExceptionClass, pyDeep.InitialCauseClass)
			} else if pyDeep.ExceptionClass != "" {
				res.ErrorClass = pyDeep.ExceptionClass
			}
			if pyDeep.CulpritCode != nil {
				res.CulpritCode = pyDeep.CulpritCode
				res.ErrorLocation = fmt.Sprintf("%s:%d", pyDeep.CulpritCode.File, pyDeep.CulpritCode.Line)
			}
			if pyDeep.ExceptionClass == "CircularImportError" {
				res.MatchedRule.RootCause = "CircularImportError"
			}
			if pyDeep.MissingPackage != "" {
				res.MatchedRule.RootCause = "PythonModuleNotFound"
			}
			if pyDeep.SummaryKo != "" {
				res.Summary = pyDeep.SummaryKo
			}
			if pyDeep.SuggestedFixKo != "" {
				res.RecommendedAction = pyDeep.SuggestedFixKo
			}
			return res
		}
	}

	// 2. Java / Spring Deep Analysis
	if strings.Contains(processedLogs, "\tat ") && (strings.Contains(processedLogs, "Exception") || strings.Contains(processedLogs, "Error") || strings.Contains(processedLogs, "# Problematic frame:")) {
		javaDeep := knowledge.AnalyzeJavaDeepCrash(processedLogs)
		if javaDeep != nil {
			if res == nil || res.MatchedRule == nil {
				res = &LogAnalysisResult{
					MatchedRule: &LogRule{
						Name:              "JavaDeepCrash",
						Category:          "Application",
						RootCause:         "JVMHeapOOM",
						Confidence:        "High",
						RecommendedAction: "Inspect Java stack trace and exception root cause.",
					},
					MatchedPattern: "JavaDeepCrash",
					Category:       "Application",
					Snippet:        tailSnippet,
				}
			}
			if javaDeep.IsUnwrapped && javaDeep.RootExceptionClass != "" {
				res.ErrorClass = javaDeep.RootExceptionClass
				if strings.Contains(javaDeep.RootExceptionClass, "LazyInitializationException") {
					res.MatchedRule.RootCause = "LazyInitializationException"
				} else if strings.Contains(javaDeep.RootExceptionClass, "TransientPropertyValueException") {
					res.MatchedRule.RootCause = "TransientPropertyValueException"
				}
			}
			if strings.Contains(processedLogs, "form a cycle:") {
				res.MatchedRule.RootCause = "SpringCircularDependency"
			}
			if javaDeep.CulpritCode != nil {
				res.CulpritCode = javaDeep.CulpritCode
				res.ErrorLocation = fmt.Sprintf("%s:%d", javaDeep.CulpritCode.File, javaDeep.CulpritCode.Line)
			}
			if javaDeep.SummaryKo != "" {
				res.Summary = javaDeep.SummaryKo
			}
			if javaDeep.SuggestedFixKo != "" {
				res.RecommendedAction = javaDeep.SuggestedFixKo
			}
			return res
		}
	}

	// 3. Node.js Deep Analysis
	if strings.Contains(processedLogs, "at ") && (strings.Contains(processedLogs, "Error") || strings.Contains(processedLogs, "unhandledRejection") || strings.Contains(processedLogs, "UnhandledPromiseRejection") || strings.Contains(processedLogs, "FATAL ERROR:")) {
		nodeDeep := knowledge.AnalyzeNodeDeepCrash(processedLogs)
		if nodeDeep != nil {
			if res == nil || res.MatchedRule == nil {
				res = &LogAnalysisResult{
					MatchedRule: &LogRule{
						Name:              "NodeDeepCrash",
						Category:          "Application",
						RootCause:         "NodeTypeError",
						Confidence:        "High",
						RecommendedAction: "Inspect Node.js stack trace and error origin.",
					},
					MatchedPattern: "NodeDeepCrash",
					Category:       "Application",
					Snippet:        tailSnippet,
				}
			}
			if nodeDeep.IsUnhandledRejection {
				res.MatchedRule.RootCause = "NodeUnhandledPromiseRejection"
			}
			if nodeDeep.PrismaCode != "" {
				res.MatchedRule.RootCause = "NodePrismaError"
				res.ErrorClass = "Prisma_" + nodeDeep.PrismaCode
			}
			if strings.Contains(processedLogs, "exports is not defined") || strings.Contains(processedLogs, "require is not defined") || strings.Contains(processedLogs, "Cannot use import statement") {
				res.MatchedRule.RootCause = "NodeESMMismatch"
				res.ErrorClass = "ESMMismatch"
			}
			if nodeDeep.CulpritCode != nil {
				res.CulpritCode = nodeDeep.CulpritCode
				res.ErrorLocation = fmt.Sprintf("%s:%d", nodeDeep.CulpritCode.File, nodeDeep.CulpritCode.Line)
			}
			if nodeDeep.SummaryKo != "" {
				res.Summary = nodeDeep.SummaryKo
			}
			if nodeDeep.SuggestedFixKo != "" {
				res.RecommendedAction = nodeDeep.SuggestedFixKo
			}
			return res
		}
	}

	// 4. Service Mesh, Ingress & Envoy Deep Analysis
	meshDeep := knowledge.AnalyzeMeshLogs(processedLogs)
	if meshDeep != nil {
		if res == nil || res.MatchedRule == nil {
			res = &LogAnalysisResult{
				MatchedRule: &LogRule{
					Name:              "MeshDeepAnalysis_" + meshDeep.Component,
					Category:          "Dependency",
					RootCause:         meshDeep.RootCause,
					Confidence:        "High",
					RecommendedAction: meshDeep.SuggestedFixKo,
				},
				MatchedPattern: "MeshDeepAnalysis_" + meshDeep.Component,
				Category:       "Dependency",
				Snippet:        tailSnippet,
			}
		} else {
			res.MatchedRule.RootCause = meshDeep.RootCause
		}
		res.ErrorClass = meshDeep.ErrorClass
		if meshDeep.SummaryKo != "" {
			res.Summary = meshDeep.SummaryKo
		}
		if meshDeep.SuggestedFixKo != "" {
			res.RecommendedAction = meshDeep.SuggestedFixKo
		}
		return res
	}

	// 5. Enterprise Cloud-Native OSS Deep Analysis
	entDeep := knowledge.AnalyzeEnterpriseOSSLogs(processedLogs)
	if entDeep != nil {
		if res == nil || res.MatchedRule == nil {
			category := "Infrastructure"
			if entDeep.Component == "vault" || entDeep.Component == "vault-agent" || entDeep.Component == "cert-manager" {
				category = "Configuration"
			} else if entDeep.Component == "patroni" || entDeep.Component == "elasticsearch" || entDeep.Component == "argocd" {
				category = "Dependency"
			}
			res = &LogAnalysisResult{
				MatchedRule: &LogRule{
					Name:              "EnterpriseOSS_" + entDeep.Component,
					Category:          category,
					RootCause:         entDeep.RootCause,
					Confidence:        "High",
					RecommendedAction: entDeep.SuggestedFixKo,
				},
				MatchedPattern: "EnterpriseOSS_" + entDeep.Component,
				Category:       category,
				Snippet:        tailSnippet,
			}
		} else {
			res.MatchedRule.RootCause = entDeep.RootCause
		}
		res.ErrorClass = entDeep.ErrorClass
		if entDeep.SummaryKo != "" {
			res.Summary = entDeep.SummaryKo
		}
		if entDeep.SuggestedFixKo != "" {
			res.RecommendedAction = entDeep.SuggestedFixKo
		}
		return res
	}

	// 6. Google Cloud SDK Deep Analysis (BigQuery, Gemini, GCS, Auth)
	gcpDeep := knowledge.AnalyzeGCPSDKLogs(processedLogs)
	if gcpDeep != nil {
		category := "Dependency"
		if gcpDeep.Component == "gcp-auth" {
			category = "Configuration"
		}
		if res == nil || res.MatchedRule == nil {
			res = &LogAnalysisResult{
				MatchedRule: &LogRule{
					Name:              "GCPSDK_" + gcpDeep.Component,
					Category:          category,
					RootCause:         gcpDeep.RootCause,
					Confidence:        "High",
					RecommendedAction: gcpDeep.SuggestedFixKo,
				},
				MatchedPattern: "GCPSDK_" + gcpDeep.Component,
				Category:       category,
				Snippet:        tailSnippet,
			}
		} else {
			res.MatchedRule.RootCause = gcpDeep.RootCause
		}
		res.ErrorClass = gcpDeep.ErrorClass
		if gcpDeep.SummaryKo != "" {
			res.Summary = gcpDeep.SummaryKo
		}
		if gcpDeep.SuggestedFixKo != "" {
			res.RecommendedAction = gcpDeep.SuggestedFixKo
		}
		return res
	}

	// 7. Data Infrastructure Deep Analysis (ClickHouse, ZooKeeper, Valkey, PostgreSQL)
	dataDeep := knowledge.AnalyzeDataInfraLogs(processedLogs)
	if dataDeep != nil {
		category := "Dependency"
		if dataDeep.Component == "clickhouse" || dataDeep.Component == "postgresql" {
			category = "Application"
		}
		if res == nil || res.MatchedRule == nil {
			res = &LogAnalysisResult{
				MatchedRule: &LogRule{
					Name:              "DataInfra_" + dataDeep.Component,
					Category:          category,
					RootCause:         dataDeep.RootCause,
					Confidence:        "High",
					RecommendedAction: dataDeep.SuggestedFixKo,
				},
				MatchedPattern: "DataInfra_" + dataDeep.Component,
				Category:       category,
				Snippet:        tailSnippet,
			}
		} else {
			res.MatchedRule.RootCause = dataDeep.RootCause
		}
		res.ErrorClass = dataDeep.ErrorClass
		if dataDeep.SummaryKo != "" {
			res.Summary = dataDeep.SummaryKo
		}
		if dataDeep.SuggestedFixKo != "" {
			res.RecommendedAction = dataDeep.SuggestedFixKo
		}
		return res
	}

	// 8. CI/CD & GitOps Deep Analysis (Jenkins, Nexus, Argo Workflows, Argo Rollouts)
	cicdDeep := knowledge.AnalyzeCICDGitOpsLogs(processedLogs)
	if cicdDeep != nil {
		category := "Application"
		if cicdDeep.Component == "argo-workflows" || cicdDeep.Component == "argo-rollouts" {
			category = "Dependency"
		}
		if res == nil || res.MatchedRule == nil {
			res = &LogAnalysisResult{
				MatchedRule: &LogRule{
					Name:              "CICDGitOps_" + cicdDeep.Component,
					Category:          category,
					RootCause:         cicdDeep.RootCause,
					Confidence:        "High",
					RecommendedAction: cicdDeep.SuggestedFixKo,
				},
				MatchedPattern: "CICDGitOps_" + cicdDeep.Component,
				Category:       category,
				Snippet:        tailSnippet,
			}
		} else {
			res.MatchedRule.RootCause = cicdDeep.RootCause
		}
		res.ErrorClass = cicdDeep.ErrorClass
		if cicdDeep.SummaryKo != "" {
			res.Summary = cicdDeep.SummaryKo
		}
		if cicdDeep.SuggestedFixKo != "" {
			res.RecommendedAction = cicdDeep.SuggestedFixKo
		}
		return res
	}

	// 9. Policy & Security Deep Analysis (Kyverno, Gatekeeper, VSO, Secrets Store CSI)
	secDeep := knowledge.AnalyzeSecurityPolicyLogs(processedLogs)
	if secDeep != nil {
		category := "Configuration"
		if res == nil || res.MatchedRule == nil {
			res = &LogAnalysisResult{
				MatchedRule: &LogRule{
					Name:              "SecurityPolicy_" + secDeep.Component,
					Category:          category,
					RootCause:         secDeep.RootCause,
					Confidence:        "High",
					RecommendedAction: secDeep.SuggestedFixKo,
				},
				MatchedPattern: "SecurityPolicy_" + secDeep.Component,
				Category:       category,
				Snippet:        tailSnippet,
			}
		} else {
			res.MatchedRule.RootCause = secDeep.RootCause
		}
		res.ErrorClass = secDeep.ErrorClass
		if secDeep.SummaryKo != "" {
			res.Summary = secDeep.SummaryKo
		}
		if secDeep.SuggestedFixKo != "" {
			res.RecommendedAction = secDeep.SuggestedFixKo
		}
		return res
	}

	// 10. Cluster Addons & AI Deep Analysis (NFS, Kube-DNS, Metrics-Server, LiteLLM)
	clusterDeep := knowledge.AnalyzeClusterInfraLogs(processedLogs)
	if clusterDeep != nil {
		category := "Infrastructure"
		if clusterDeep.Component == "litellm" {
			category = "Dependency"
		}
		if res == nil || res.MatchedRule == nil {
			res = &LogAnalysisResult{
				MatchedRule: &LogRule{
					Name:              "ClusterAddon_" + clusterDeep.Component,
					Category:          category,
					RootCause:         clusterDeep.RootCause,
					Confidence:        "High",
					RecommendedAction: clusterDeep.SuggestedFixKo,
				},
				MatchedPattern: "ClusterAddon_" + clusterDeep.Component,
				Category:       category,
				Snippet:        tailSnippet,
			}
		} else {
			res.MatchedRule.RootCause = clusterDeep.RootCause
		}
		res.ErrorClass = clusterDeep.ErrorClass
		if clusterDeep.SummaryKo != "" {
			res.Summary = clusterDeep.SummaryKo
		}
		if clusterDeep.SuggestedFixKo != "" {
			res.RecommendedAction = clusterDeep.SuggestedFixKo
		}
		return res
	}

	// 11. Network, SSL/TLS & HTTP Forward Proxy (Squid) Deep Analysis
	netTLSDeep := knowledge.AnalyzeNetTLSProxyLogs(processedLogs)
	if netTLSDeep != nil {
		category := "Dependency"
		if netTLSDeep.Component == "tls" {
			category = "Configuration"
		} else if netTLSDeep.Component == "network" {
			category = "Infrastructure"
		}
		if res == nil || res.MatchedRule == nil {
			res = &LogAnalysisResult{
				MatchedRule: &LogRule{
					Name:              "NetTLSProxy_" + netTLSDeep.Component,
					Category:          category,
					RootCause:         netTLSDeep.RootCause,
					Confidence:        "High",
					RecommendedAction: netTLSDeep.SuggestedFixKo,
				},
				MatchedPattern: "NetTLSProxy_" + netTLSDeep.Component,
				Category:       category,
				Snippet:        tailSnippet,
			}
		} else {
			res.MatchedRule.RootCause = netTLSDeep.RootCause
		}
		res.ErrorClass = netTLSDeep.ErrorClass
		if netTLSDeep.SummaryKo != "" {
			res.Summary = netTLSDeep.SummaryKo
		}
		if netTLSDeep.SuggestedFixKo != "" {
			res.RecommendedAction = netTLSDeep.SuggestedFixKo
		}
		return res
	}

	return res
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
	rustLocRegex   = regexp.MustCompile(`at\s+([^:\s]+):(\d+):(\d+)`)
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
		// Skip python internal standard library and virtualenvs
		if strings.Contains(filePath, "site-packages") ||
			strings.Contains(filePath, "lib/python") ||
			strings.Contains(filePath, ".venv") ||
			strings.Contains(filePath, "virtualenv") ||
			strings.Contains(filePath, "venv/") {
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

var pythonExcRegex = regexp.MustCompile(`(?m)^([A-Za-z_][A-Za-z0-9_]*(?:Error|Exception|Warning|Interrupt))(?::\s*(.*))?$`)

func extractPythonExceptionClass(logs string) string {
	matches := pythonExcRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) > 0 {
		return matches[len(matches)-1][1]
	}
	return "PythonException"
}

func extractPythonExceptionDetail(logs string) string {
	matches := pythonExcRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) > 0 {
		last := matches[len(matches)-1]
		if len(last) > 2 && last[2] != "" {
			return last[1] + ": " + last[2]
		}
		return last[1]
	}
	return "Python unhandled exception"
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
	// Walk through stack to find user code (ignoring Spring/JDK/logging internal calls)
	for _, m := range matches {
		fullPkg := m[1]
		fileName := m[2]
		lineStr := m[3]
		if strings.HasPrefix(fullPkg, "org.springframework.") ||
			strings.HasPrefix(fullPkg, "java.") ||
			strings.HasPrefix(fullPkg, "javax.") ||
			strings.HasPrefix(fullPkg, "jakarta.") ||
			strings.HasPrefix(fullPkg, "sun.") ||
			strings.HasPrefix(fullPkg, "jdk.") ||
			strings.HasPrefix(fullPkg, "org.apache.") ||
			strings.HasPrefix(fullPkg, "com.zaxxer.") ||
			strings.HasPrefix(fullPkg, "io.netty.") ||
			strings.HasPrefix(fullPkg, "ch.qos.logback.") ||
			strings.HasPrefix(fullPkg, "org.slf4j.") {
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
		if strings.Contains(filePath, "node_modules") || strings.Contains(filePath, "node:internal") {
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

var cppLocRegex = regexp.MustCompile(`(?:(?:\.\/|[a-zA-Z0-9_\-\.\/]+)\/)?([a-zA-Z0-9_\-\.]+\.(?:cpp|c|cc|cxx|h|hpp)):(\d+)`)

func extractCppLocation(logs string) string {
	matches := cppLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) > 0 {
		return matches[0][1] + ":" + matches[0][2]
	}
	return ""
}

func extractCppCulprit(logs string) *observerv1alpha1.CulpritCode {
	matches := cppLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) == 0 {
		return nil
	}
	for _, m := range matches {
		file := m[1]
		if strings.HasPrefix(file, "libc.") || strings.HasPrefix(file, "libstdc++") {
			continue
		}
		lineNum, _ := strconv.Atoi(m[2])
		return &observerv1alpha1.CulpritCode{
			Language: "C/C++",
			File:     file,
			Line:     lineNum,
		}
	}
	return nil
}

func extractRustLocation(logs string) string {
	matches := rustLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) > 0 {
		parts := strings.Split(matches[0][1], "/")
		return parts[len(parts)-1] + ":" + matches[0][2]
	}
	return ""
}

func extractRustCulprit(logs string) *observerv1alpha1.CulpritCode {
	matches := rustLocRegex.FindAllStringSubmatch(logs, -1)
	if len(matches) == 0 {
		return nil
	}
	for _, m := range matches {
		filePath := m[1]
		if strings.Contains(filePath, "library/core") || strings.Contains(filePath, "library/std") || strings.Contains(filePath, "rustc/") {
			continue
		}
		lineNum, _ := strconv.Atoi(m[2])
		parts := strings.Split(filePath, "/")
		return &observerv1alpha1.CulpritCode{
			Language: "Rust",
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
