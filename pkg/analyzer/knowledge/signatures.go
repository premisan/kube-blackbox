package knowledge

import (
	"regexp"
)

// Signature defines a crash pattern with comprehensive deterministic metadata.
type Signature struct {
	ID                string
	Domain            string // jvm, go, python, node, dotnet, rust, cpp, php, ruby, database, network, storage
	Category          string // Application, Infrastructure, Configuration, Dependency
	RootCause         string
	Confidence        string
	Pattern           *regexp.Regexp
	SummaryKo         string
	ActionKo          string
	SummaryEn         string
	ActionEn          string
	ErrorClass        string
}

// EmbeddedSignatures is the comprehensive embedded catalog of crash signatures across all major runtimes.
var EmbeddedSignatures = []Signature{
	// ==================== C / C++ / glibc / Native ====================
	{
		ID:         "NATIVE-GLIBC-CORRUPTION",
		Domain:     "cpp",
		Category:   "Application",
		RootCause:  "HeapCorruption",
		Confidence: "High",
		Pattern:    regexp.MustCompile(`(?i)(?:malloc\(\):\s*corrupted top size|double free or corruption|corrupted size vs\. prev_size|free\(\):\s*invalid pointer)`),
		SummaryKo:  "glibc 힙 메모리 손상 (Double Free 또는 잘못된 포인터 해제)",
		ActionKo:   "C/C++ 네이티브 모듈 또는 CGO/JNI 바인딩에서 메모리 이중 해제(Double Free) 및 버퍼 오버플로우를 AddressSanitizer(ASan)로 디버깅하십시오.",
		SummaryEn:  "glibc heap corruption detected (Double free or invalid pointer free)",
		ActionEn:   "Debug native extensions or CGO/JNI modules for double free and buffer overflows using AddressSanitizer (ASan).",
		ErrorClass: "GlibcHeapCorruption",
	},
	{
		ID:         "NATIVE-STACK-SMASH",
		Domain:     "cpp",
		Category:   "Application",
		RootCause:  "StackSmashing",
		Confidence: "High",
		Pattern:    regexp.MustCompile(`(?i)\*\*\* stack smashing detected \*\*\*:\s*terminated`),
		SummaryKo:  "스택 버퍼 오버플로우로 인한 스택 카나리(Stack Canary) 보호 메커니즘 발동",
		ActionKo:   "로컬 배열 크기를 초과하여 쓴 메모리 접근 코드를 찾고 스택 버퍼 크기를 안전하게 검증하십시오.",
		SummaryEn:  "Stack buffer overflow detected by GCC stack protector",
		ActionEn:   "Fix buffer overruns in local stack variables and ensure strict bounds checking in C/C++ code.",
		ErrorClass: "StackSmashingDetected",
	},

	// ==================== JVM / hs_err_pid Native Crash ====================
	{
		ID:         "JVM-FATAL-CRASH-DUMP",
		Domain:     "jvm",
		Category:   "Application",
		RootCause:  "JVMNativeCrashDump",
		Confidence: "High",
		Pattern:    regexp.MustCompile(`(?i)(?:# A fatal error has been detected by the Java Runtime Environment|# Problematic frame:\s*#\s*([CjV]\s+\[.+?\])|# Failed to write core dump)`),
		SummaryKo:  "JVM 내부 네이티브 크래시 (hs_err_pid 치명적 오류 덤프 생성)",
		ActionKo:   "문제 발생 프레임(Problematic frame)의 JNI 네이티브 라이브러리(.so/.dll) 또는 JVM 버전 버그 여부를 확인하십시오.",
		SummaryEn:  "Fatal JVM native crash detected (hs_err_pid crash report created)",
		ActionEn:   "Inspect the problematic native frame in hs_err_pid log for incompatible JNI drivers or JVM bugs.",
		ErrorClass: "JVMNativeFatalCrash",
	},

	// ==================== Python / Faulthandler & Memory ====================
	{
		ID:         "PYTHON-FAULTHANDLER-CRASH",
		Domain:     "python",
		Category:   "Application",
		RootCause:  "PythonNativeExtensionCrash",
		Confidence: "High",
		Pattern:    regexp.MustCompile(`(?i)(?:Fatal Python error:\s*Segmentation fault|Fatal Python error:\s*Aborted|Current thread 0x[0-9a-f]+ \(most recent call first\):)`),
		SummaryKo:  "파이썬 faulthandler에 의해 캡처된 네이티브 확장 모듈 치명적 크래시 (SIGSEGV/SIGABRT)",
		ActionKo:   "NumPy, PyTorch, Pandas 등 C/C++로 컴파일된 파이썬 바이너리 모듈의 버전 호환성 및 메모리 정렬을 점검하십시오.",
		SummaryEn:  "Fatal Python native crash caught by faulthandler (SIGSEGV/SIGABRT)",
		ActionEn:   "Check compiled C-extensions (NumPy, PyTorch, Cython) for memory corruption or ABI version conflicts.",
		ErrorClass: "PythonNativeCrash",
	},

	// ==================== Node.js / V8 Fatal Error ====================
	{
		ID:         "NODE-V8-FATAL-ERROR",
		Domain:     "node",
		Category:   "Application",
		RootCause:  "NodeV8FatalError",
		Confidence: "High",
		Pattern:    regexp.MustCompile(`(?i)(?:<--- Last few GCs --->|FATAL ERROR:\s*(.+?)\s+Allocation failed - JavaScript heap out of memory|FATAL ERROR:\s*CALL_AND_RETRY_LAST)`),
		SummaryKo:  "V8 엔진 치명적 오류: JavaScript 힙 메모리 할당 실패 (OOM)",
		ActionKo:   "Node.js 기동 인자에 '--max-old-space-size'를 확장하거나 메모리 누수(Event emitter, 캐시 등)를 프로파일링하십시오.",
		SummaryEn:  "Node.js V8 fatal crash: JavaScript heap out of memory",
		ActionEn:   "Increase '--max-old-space-size' in NODE_OPTIONS or profile memory leaks in object caches.",
		ErrorClass: "V8HeapOutOfMemory",
	},

	// ==================== Storage / Filesystem OS Constraints ====================
	{
		ID:         "STORAGE-READONLY-FS",
		Domain:     "storage",
		Category:   "Configuration",
		RootCause:  "ReadOnlyFilesystemError",
		Confidence: "High",
		Pattern:    regexp.MustCompile(`(?i)(?:read-only file system|EROFS:\s*read-only file system|open\s+(.+?):\s*read-only file system)`),
		SummaryKo:  "읽기 전용 파일시스템(EROFS) 쓰기 시도로 인한 프로세스 중단",
		ActionKo:   "파드 SecurityContext의 readOnlyRootFilesystem 설정을 확인하고, 쓰기가 필요한 디렉토리(/tmp, /var/log 등)를 emptyDir 볼륨으로 마운트하십시오.",
		SummaryEn:  "Operation failed due to Read-only file system (EROFS)",
		ActionEn:   "Check readOnlyRootFilesystem in pod securityContext and mount emptyDir volumes for writable paths like /tmp.",
		ErrorClass: "EROFS",
	},
	{
		ID:         "STORAGE-FILE-DESCRIPTOR-LIMIT",
		Domain:     "storage",
		Category:   "Infrastructure",
		RootCause:  "FileDescriptorLimitExceeded",
		Confidence: "High",
		Pattern:    regexp.MustCompile(`(?i)(?:too many open files|EMFILE:\s*too many open files|ENFILE:\s*file table overflow)`),
		SummaryKo:  "프로세스 또는 시스템 파일 디스크립터(FD) 한도 고갈 (EMFILE / ENFILE)",
		ActionKo:   "소켓 또는 파일 핸들이 close()되지 않고 누수되는지 확인하거나, 컨테이너 ulimit(nofile) 및 노드 fs.file-max 한도를 확장하십시오.",
		SummaryEn:  "File descriptor table exhausted (EMFILE / ENFILE)",
		ActionEn:   "Fix file/socket descriptor leaks in application code or increase container ulimit (nofile).",
		ErrorClass: "EMFILE_ENFILE",
	},

	// ==================== Network & CoreDNS ====================
	{
		ID:         "NETWORK-COREDNS-TIMEOUT",
		Domain:     "network",
		Category:   "Dependency",
		RootCause:  "DNSResolutionFailure",
		Confidence: "High",
		Pattern:    regexp.MustCompile(`(?i)(?:i/o timeout.+dial udp.+:53|Temporary failure in name resolution|getaddrinfo EAI_AGAIN|EAI_NONAME)`),
		SummaryKo:  "CoreDNS 도메인 이름 해석 타임아웃 또는 실패",
		ActionKo:   "kube-system CoreDNS 파드 상태 및 부하를 점검하고, 파드 spec의 dnsConfig options(ndots:2 등) 최적화를 검토하십시오.",
		SummaryEn:  "DNS resolution timeout or lookup failure via cluster CoreDNS",
		ActionEn:   "Check CoreDNS pod health and latency, or optimize dnsConfig options (ndots tuning) in pod spec.",
		ErrorClass: "DNSResolutionTimeout",
	},
}
