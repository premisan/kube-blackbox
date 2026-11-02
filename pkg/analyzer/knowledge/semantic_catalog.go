package knowledge

import (
	"fmt"
	"strings"
	"sync"
)

// SemanticCatalogEntry holds the deep diagnostic intelligence for a specific error class or condition.
type SemanticCatalogEntry struct {
	ErrorClass        string   // KeyError, NullPointerException, TypeError, etc.
	Language          string   // Python, Java, Node.js, Go, Database, Infrastructure, System
	Category          string   // Application, Dependency, Configuration, Infrastructure
	RootCause         string   // Standardized diagnostic root cause code
	SummaryKo         string   // Deep diagnostic summary in Korean (LLM-grade clarity)
	ActionKo          string   // Actionable 2-3 step resolution guide in Korean
	SummaryEn         string   // Diagnostic summary in English
	ActionEn          string   // Actionable resolution guide in English
	RootCauseChainKo  []string // Sentry-grade 3-4 step causal breakdown in Korean
	RootCauseChainEn  []string // 3-4 step causal breakdown in English
	InferredContextKo string   // Business and runtime context explanation in Korean
	InferredContextEn string   // Runtime context explanation in English
	SuggestedFixKo    string   // Concrete code / CLI / config resolution instructions in Korean
	SuggestedFixEn    string   // Concrete resolution instructions in English
}

// SemanticCatalog is the high-performance O(1) in-memory knowledge base containing hundreds of
// pre-indexed runtime exceptions, framework faults, and operational failure modes.
var (
	SemanticCatalog    = make(map[string]SemanticCatalogEntry, 2048)
	catalogInitOnce    sync.Once
	registeredCatalogs []func()
)

// RegisterCatalogLoader registers a domain-specific catalog loader function.
func RegisterCatalogLoader(loader func()) {
	registeredCatalogs = append(registeredCatalogs, loader)
	// If already initialized, run immediately
	if len(SemanticCatalog) > 0 {
		loader()
	}
}

func init() {
	// Auto-run registered loaders on package init
	for _, loader := range registeredCatalogs {
		loader()
	}
}

// RegisterCatalogEntries indexes a slice of SemanticCatalogEntry into the O(1) lookup table.
func RegisterCatalogEntries(entries []SemanticCatalogEntry) {
	for _, entry := range entries {
		// Populate intelligent defaults if omitted
		if entry.SuggestedFixKo == "" {
			entry.SuggestedFixKo = entry.ActionKo
		}
		if entry.SuggestedFixEn == "" {
			entry.SuggestedFixEn = entry.ActionEn
		}
		if entry.InferredContextKo == "" {
			entry.InferredContextKo = entry.SummaryKo
		}
		if entry.InferredContextEn == "" {
			entry.InferredContextEn = entry.SummaryEn
		}
		if len(entry.RootCauseChainKo) == 0 {
			name := entry.ErrorClass
			if name == "" {
				name = entry.RootCause
			}
			entry.RootCauseChainKo = []string{
				fmt.Sprintf("애플리케이션 런타임에서 %s 오류가 발생함", name),
				"상위 호출 스택에 예외 처리 핸들러가 누락되어 런타임 언와인딩 발생",
				"비정상 종료 코드와 함께 프로세스가 강제 중단되고 Kubelet에 의해 재시작됨",
			}
		}
		if len(entry.RootCauseChainEn) == 0 {
			name := entry.ErrorClass
			if name == "" {
				name = entry.RootCause
			}
			entry.RootCauseChainEn = []string{
				fmt.Sprintf("Application runtime encountered %s error", name),
				"Unhandled exception propagated up the call stack triggering runtime unwinding",
				"Process terminated with non-zero exit code and was restarted by Kubelet",
			}
		}

		langLower := strings.ToLower(entry.Language)
		errLower := strings.ToLower(entry.ErrorClass)
		rootLower := strings.ToLower(entry.RootCause)

		if errLower != "" {
			SemanticCatalog[errLower] = entry
			if langLower != "" {
				SemanticCatalog[langLower+":"+errLower] = entry
			}
		}
		if rootLower != "" {
			SemanticCatalog[rootLower] = entry
			if langLower != "" {
				SemanticCatalog[langLower+":"+rootLower] = entry
			}
		}
	}
}

// LookupSemanticCatalog performs an O(1) microsecond lookup by language and key (errorClass or rootCause).
func LookupSemanticCatalog(lang, key string) (SemanticCatalogEntry, bool) {
	if key == "" {
		return SemanticCatalogEntry{}, false
	}
	keyLower := strings.ToLower(strings.TrimSpace(key))
	langLower := strings.ToLower(strings.TrimSpace(lang))

	// 1. Language-qualified lookup: "python:keyerror", "java:nullpointerexception"
	if langLower != "" {
		if entry, found := SemanticCatalog[langLower+":"+keyLower]; found {
			return entry, true
		}
	}

	// 2. Direct exact key lookup: "keyerror", "mysql_1213_deadlock", "postgresinfailedsqltransaction"
	if entry, found := SemanticCatalog[keyLower]; found {
		return entry, true
	}

	// 3. Fallback: Strip language prefix if present (e.g. "PythonKeyError" -> "keyerror")
	prefixes := []string{"python", "java", "node", "go", "jvm", "dotnet", "ruby", "php"}
	for _, p := range prefixes {
		if strings.HasPrefix(keyLower, p) && len(keyLower) > len(p) {
			stripped := keyLower[len(p):]
			if entry, found := SemanticCatalog[stripped]; found {
				return entry, true
			}
		}
	}

	return SemanticCatalogEntry{}, false
}

// SynthesizeDiagnosisFromUniversal enhances universal analyzer results using semantic intelligence.
func SynthesizeDiagnosisFromUniversal(u *UniversalCrashAnalysis, lang string) (rootCause string, summary string, action string) {
	if u == nil {
		return "ApplicationRuntimeError", "애플리케이션 런타임 오류가 발생했습니다.", "로그 스니펫의 스택트레이스를 확인하여 오류를 수정하세요."
	}

	rootCause = "Universal_" + u.Language + "_" + u.ErrorClass

	locStr := ""
	if u.CulpritCode != nil && u.CulpritCode.File != "" {
		if u.CulpritCode.Line > 0 {
			locStr = fmt.Sprintf(" (%s:%d)", u.CulpritCode.File, u.CulpritCode.Line)
		} else {
			locStr = fmt.Sprintf(" (%s)", u.CulpritCode.File)
		}
	}

	entry, found := LookupSemanticCatalog(u.Language, u.ErrorClass)

	if found {
		if lang == "ko" {
			summary = entry.SummaryKo + locStr
			action = entry.ActionKo
		} else {
			summary = entry.SummaryEn + locStr
			action = entry.ActionEn
		}
		if entry.RootCause != "" {
			rootCause = entry.RootCause
		}
		return
	}

	// Dynamic fallback
	if lang == "ko" {
		summary = fmt.Sprintf("[%s] %s 예외가 처리되지 않아 프로세스가 종료되었습니다%s", strings.ToUpper(u.Language), u.ErrorClass, locStr)
		action = fmt.Sprintf("1) %s 지점에 예외 처리(try-catch/recover)를 추가하세요. 2) 입력 데이터 및 종속성 상태를 점검하세요.", u.ErrorLocation)
	} else {
		summary = fmt.Sprintf("[%s] Unhandled %s terminated the process%s", strings.ToUpper(u.Language), u.ErrorClass, locStr)
		action = fmt.Sprintf("1) Add error handling around %s. 2) Validate input data and upstream state.", u.ErrorLocation)
	}
	return
}
