package knowledge

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
)

// PythonFrame represents a single stack frame from a Python traceback.
type PythonFrame struct {
	File     string
	Line     int
	Function string
	Code     string
	IsUser   bool
}

// PythonDeepAnalysis holds the deep diagnostic findings extracted from Python crash logs.
type PythonDeepAnalysis struct {
	ExceptionClass     string
	ExceptionMessage   string
	IsChained          bool
	InitialCauseClass  string
	InitialCauseMsg    string
	Framework          string
	CulpritCode        *observerv1alpha1.CulpritCode
	CodeSnippet        string
	SuggestedFix       string
	SuggestedFixKo     string
	SummaryKo          string
	SummaryEn          string
	MissingPackage     string // PyPI package name if ModuleNotFoundError
	CircularImportPair [2]string
}

// EmbeddedPipCatalog maps Python import module names to their canonical PyPI distribution names.
var EmbeddedPipCatalog = map[string]string{
	"yaml":             "PyYAML",
	"cv2":              "opencv-python",
	"PIL":              "Pillow",
	"psycopg2":         "psycopg2-binary",
	"dateutil":         "python-dateutil",
	"bs4":              "beautifulsoup4",
	"dotenv":           "python-dotenv",
	"jose":             "python-jose[cryptography]",
	"jwt":              "PyJWT",
	"sklearn":          "scikit-learn",
	"fitz":             "PyMuPDF",
	"magic":            "python-magic",
	"docx":             "python-docx",
	"pptx":             "python-pptx",
	"serial":           "pyserial",
	"usb":              "pyusb",
	"crypto":           "pycryptodome",
	"Crypto":           "pycryptodome",
	"git":              "GitPython",
	"OpenSSL":          "pyOpenSSL",
	"attr":             "attrs",
	"pydantic_core":    "pydantic",
	"starlette":        "starlette",
	"fastapi":          "fastapi",
	"uvicorn":          "uvicorn",
	"gunicorn":         "gunicorn",
	"sqlalchemy":       "SQLAlchemy",
	"alembic":          "alembic",
	"redis":            "redis",
	"celery":           "celery",
	"kombu":            "kombu",
	"billiard":         "billiard",
	"pika":             "pika",
	"kafka":            "kafka-python",
	"aiokafka":         "aiokafka",
	"aiohttp":          "aiohttp",
	"httpx":            "httpx",
	"requests":         "requests",
	"urllib3":          "urllib3",
	"boto3":            "boto3",
	"botocore":         "botocore",
	"google.cloud":     "google-cloud-storage",
	"azure":            "azure-storage-blob",
	"grpc":             "grpcio",
	"google.protobuf":  "protobuf",
	"tornado":          "tornado",
	"flask":            "Flask",
	"django":           "Django",
	"numpy":            "numpy",
	"pandas":           "pandas",
	"scipy":            "scipy",
	"matplotlib":       "matplotlib",
	"seaborn":          "seaborn",
	"torch":            "torch",
	"torchvision":      "torchvision",
	"transformers":     "transformers",
	"accelerate":       "accelerate",
	"datasets":         "datasets",
	"safetensors":      "safetensors",
	"timm":             "timm",
	"openai":           "openai",
	"anthropic":        "anthropic",
	"langchain":        "langchain",
	"chromadb":         "chromadb",
	"weaviate":         "weaviate-client",
	"qdrant_client":    "qdrant-client",
	"elasticsearch":    "elasticsearch",
	"pymongo":          "pymongo",
	"motor":            "motor",
	"mysql":            "mysql-connector-python",
	"pymysql":          "PyMySQL",
	"asyncpg":          "asyncpg",
	"tortoise":         "tortoise-orm",
	"peewee":           "peewee",
	"orjson":           "orjson",
	"ujson":            "ujson",
	"msgpack":          "msgpack",
	"marshmallow":      "marshmallow",
	"schematics":       "schematics",
	"cerberus":         "cerberus",
	"click":            "click",
	"typer":            "typer",
	"rich":             "rich",
	"loguru":           "loguru",
	"structlog":        "structlog",
	"prometheus_client": "prometheus-client",
	"opentelemetry":    "opentelemetry-api",
	"sentry_sdk":       "sentry-sdk",
	"pytest":           "pytest",
	"mock":             "mock",
	"faker":            "Faker",
	"freezegun":        "freezegun",
	"factory":          "factory-boy",
	"black":            "black",
	"flake8":           "flake8",
	"mypy":             "mypy",
	"ruff":             "ruff",
	"pylint":           "pylint",
	"isort":            "isort",
	"wheel":            "wheel",
	"setuptools":       "setuptools",
	"pip":              "pip",
	"virtualenv":       "virtualenv",
	"tox":              "tox",
	"poetry":           "poetry",
	"flit":             "flit",
	"hatch":            "hatch",
}

// Regex patterns for deep Python traceback parsing
var (
	pyFrameRegex = regexp.MustCompile(`(?m)^\s*File "([^"]+)", line (\d+)(?:, in ([^\n\r]+))?`)
	pyExcRegex   = regexp.MustCompile(`(?m)^([A-Za-z_][A-Za-z0-9_\.]*(?:Error|Exception|Warning|Interrupt|FatalError|Exit))(?::\s*(.*))?$`)
	pyCircRegex  = regexp.MustCompile(`cannot import name '([^']+)' from partially initialized module '([^']+)' \(most likely due to a circular import\)`)
	pyModNotFoundRegex = regexp.MustCompile(`(?:No module named ['"]([^'"]+)['"]|cannot import name ['"]([^'"]+)['"])`)
	pyPydanticLocRegex = regexp.MustCompile(`(?m)^\s*([a-zA-Z0-9_\.\[\]]+)\r?\n\s+([^\r\n]+)\s+\(type=([^\)]+)\)`)
)

// ResolvePipPackage returns the canonical PyPI package for a missing Python module.
func ResolvePipPackage(moduleName string) string {
	parts := strings.Split(moduleName, ".")
	if len(parts) > 0 {
		top := parts[0]
		if pkg, ok := EmbeddedPipCatalog[top]; ok {
			return pkg
		}
	}
	if pkg, ok := EmbeddedPipCatalog[moduleName]; ok {
		return pkg
	}
	return moduleName
}

// AnalyzePythonDeepCrash performs comprehensive multi-traceback and framework-level inspection.
func AnalyzePythonDeepCrash(logs string) *PythonDeepAnalysis {
	if !strings.Contains(logs, "Traceback (most recent call last):") &&
		!strings.Contains(logs, "Fatal Python error:") {
		return nil
	}

	analysis := &PythonDeepAnalysis{}

	// 1. Check for Circular Import
	if circMatch := pyCircRegex.FindStringSubmatch(logs); len(circMatch) >= 3 {
		analysis.ExceptionClass = "CircularImportError"
		analysis.CircularImportPair = [2]string{circMatch[1], circMatch[2]}
		analysis.ExceptionMessage = fmt.Sprintf("Circular import between '%s' and '%s'", circMatch[1], circMatch[2])
		analysis.SummaryKo = fmt.Sprintf("Python 모듈 상호 순환 참조(Circular Import) 발생: '%s' <-> '%s'", circMatch[1], circMatch[2])
		analysis.SuggestedFixKo = fmt.Sprintf("1) '%s' 모듈의 임포트를 함수 내부(로컬 임포트)로 이동하거나, 2) 'from %s import ...' 대신 파일 상단에서 'import %s'로 모듈 자체를 참조하거나, 3) 공통 데이터 모델을 별도의 독립 모듈로 분리하십시오.", circMatch[1], circMatch[2], circMatch[2])
		analysis.SummaryEn = fmt.Sprintf("Python circular import detected between '%s' and '%s'", circMatch[1], circMatch[2])
		analysis.SuggestedFix = fmt.Sprintf("1) Move import inside function scope, 2) use 'import %s' instead of 'from %s import %s', or 3) refactor shared models into a separate module.", circMatch[2], circMatch[2], circMatch[1])
	}

	// 2. Chained Exception Detection
	chainSplitters := []string{
		"During handling of the above exception, another exception occurred:",
		"The above exception was the direct cause of the following exception:",
	}
	for _, splitter := range chainSplitters {
		if strings.Contains(logs, splitter) {
			analysis.IsChained = true
			sections := strings.Split(logs, splitter)
			if len(sections) >= 2 {
				// Parse root cause from initial section (first traceback)
				initialLogs := sections[0]
				initialExcMatches := pyExcRegex.FindAllStringSubmatch(initialLogs, -1)
				if len(initialExcMatches) > 0 {
					lastInitial := initialExcMatches[len(initialExcMatches)-1]
					analysis.InitialCauseClass = lastInitial[1]
					if len(lastInitial) > 2 {
						analysis.InitialCauseMsg = strings.TrimSpace(lastInitial[2])
					}
				}
			}
			break
		}
	}

	// 3. Extract Frames and Culprit User Code
	frameMatches := pyFrameRegex.FindAllStringSubmatch(logs, -1)
	var frames []PythonFrame
	for _, m := range frameMatches {
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

		frames = append(frames, PythonFrame{
			File:     filePath,
			Line:     lineNum,
			Function: fn,
			IsUser:   isUser,
		})
	}

	// Walk backwards through frames to find the culprit user frame
	for i := len(frames) - 1; i >= 0; i-- {
		f := frames[i]
		if f.IsUser {
			parts := strings.Split(f.File, "/")
			analysis.CulpritCode = &observerv1alpha1.CulpritCode{
				Language: "Python",
				File:     parts[len(parts)-1],
				Line:     f.Line,
				Function: f.Function,
			}
			analysis.CodeSnippet = f.Code
			break
		}
	}
	if analysis.CulpritCode == nil && len(frames) > 0 {
		f := frames[len(frames)-1]
		parts := strings.Split(f.File, "/")
		analysis.CulpritCode = &observerv1alpha1.CulpritCode{
			Language: "Python",
			File:     parts[len(parts)-1],
			Line:     f.Line,
			Function: f.Function,
		}
		analysis.CodeSnippet = f.Code
	}

	// 4. Extract Final Exception Class & Message
	excMatches := pyExcRegex.FindAllStringSubmatch(logs, -1)
	if len(excMatches) > 0 {
		last := excMatches[len(excMatches)-1]
		if analysis.ExceptionClass == "" {
			analysis.ExceptionClass = last[1]
		}
		if len(last) > 2 && analysis.ExceptionMessage == "" {
			analysis.ExceptionMessage = strings.TrimSpace(last[2])
		}
	}

	// 5. Detect Framework & Specific Sub-patterns
	detectFrameworkAndDomainRules(logs, analysis)

	return analysis
}

func detectFrameworkAndDomainRules(logs string, analysis *PythonDeepAnalysis) {
	lowerLogs := strings.ToLower(logs)

	// Framework Tagging
	if strings.Contains(lowerLogs, "fastapi") || strings.Contains(lowerLogs, "starlette") || strings.Contains(lowerLogs, "pydantic") {
		analysis.Framework = "FastAPI/Pydantic"
	} else if strings.Contains(lowerLogs, "django") {
		analysis.Framework = "Django"
	} else if strings.Contains(lowerLogs, "flask") || strings.Contains(lowerLogs, "werkzeug") {
		analysis.Framework = "Flask"
	} else if strings.Contains(lowerLogs, "sqlalchemy") || strings.Contains(lowerLogs, "alembic") {
		analysis.Framework = "SQLAlchemy"
	} else if strings.Contains(lowerLogs, "celery") || strings.Contains(lowerLogs, "kombu") || strings.Contains(lowerLogs, "billiard") {
		analysis.Framework = "Celery"
	} else if strings.Contains(lowerLogs, "torch") || strings.Contains(lowerLogs, "pytorch") {
		analysis.Framework = "PyTorch"
	}

	// Specific Domain Exceptions
	if strings.Contains(analysis.ExceptionClass, "ModuleNotFoundError") || strings.Contains(analysis.ExceptionClass, "ImportError") {
		if modMatch := pyModNotFoundRegex.FindStringSubmatch(analysis.ExceptionMessage); len(modMatch) >= 2 {
			mod := modMatch[1]
			if mod == "" && len(modMatch) >= 3 {
				mod = modMatch[2]
			}
			analysis.MissingPackage = ResolvePipPackage(mod)
			analysis.SummaryKo = fmt.Sprintf("Python 모듈 의존성 누락: '%s' (설치 필요: %s)", mod, analysis.MissingPackage)
			analysis.SuggestedFixKo = fmt.Sprintf("Dockerfile 또는 requirements.txt에 'pip install %s'를 추가하고 컨테이너 이미지를 재빌드하십시오.", analysis.MissingPackage)
			analysis.SummaryEn = fmt.Sprintf("Missing Python module dependency: '%s' (Package: %s)", mod, analysis.MissingPackage)
			analysis.SuggestedFix = fmt.Sprintf("Add 'pip install %s' to your requirements.txt or Dockerfile and rebuild container image.", analysis.MissingPackage)
		}
	} else if strings.Contains(analysis.ExceptionClass, "ValidationError") {
		analysis.SummaryKo = fmt.Sprintf("Pydantic 데이터 검증 실패: %s", analysis.ExceptionMessage)
		analysis.SuggestedFixKo = "API 요청/응답 페이로드 스키마를 점검하고, Optional 필드에는 기본값(None) 또는 Field(default=...)를 선언하십시오."
		analysis.SummaryEn = fmt.Sprintf("Pydantic schema validation error: %s", analysis.ExceptionMessage)
		analysis.SuggestedFix = "Inspect API request payload against Pydantic schema and ensure optional fields allow None or have default values."
	} else if strings.Contains(analysis.ExceptionClass, "OperationalError") && strings.Contains(lowerLogs, "no such table") {
		analysis.SummaryKo = "데이터베이스 테이블 부재 (마이그레이션 미적용): " + analysis.ExceptionMessage
		analysis.SuggestedFixKo = "파드 기동 전 또는 initContainer에서 데이터베이스 마이그레이션(alembic upgrade head 또는 python manage.py migrate)을 실행하십시오."
		analysis.SummaryEn = "Database table does not exist (unapplied migrations): " + analysis.ExceptionMessage
		analysis.SuggestedFix = "Run database migrations (alembic upgrade head or python manage.py migrate) via initContainer prior to application startup."
	} else if strings.Contains(analysis.ExceptionClass, "DetachedInstanceError") {
		analysis.SummaryKo = "SQLAlchemy DetachedInstanceError: 세션 종료 후 지연 로딩(Lazy Loading) 접근"
		analysis.SuggestedFixKo = "쿼리 시점 조인(joinedload/selectinload)을 사용하여 필요한 연관 객체를 사전 로드(Eager loading)하거나 세션 스코프를 확장하십시오."
		analysis.SummaryEn = "SQLAlchemy DetachedInstanceError: lazy loading attempted on detached ORM instance"
		analysis.SuggestedFix = "Use eager loading (selectinload or joinedload) at query execution time or keep the database session open."
	} else if strings.Contains(analysis.ExceptionClass, "QueuePool") || (strings.Contains(analysis.ExceptionClass, "TimeoutError") && strings.Contains(lowerLogs, "pool limit")) {
		analysis.SummaryKo = "SQLAlchemy 커넥션 풀(QueuePool) 고갈: " + analysis.ExceptionMessage
		analysis.SuggestedFixKo = "커넥션 누수(세션 close() 또는 컨텍스트 매니저 사용 여부)를 점검하고, create_engine(pool_size=..., max_overflow=...) 크기를 증설하십시오."
		analysis.SummaryEn = "SQLAlchemy QueuePool exhausted: " + analysis.ExceptionMessage
		analysis.SuggestedFix = "Ensure database sessions are closed with context managers ('with Session() as s:') and increase create_engine pool_size/max_overflow."
	}
}
