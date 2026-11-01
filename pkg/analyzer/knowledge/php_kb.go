package knowledge

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
)

// PHPAnalysis represents structured diagnostic findings from PHP CLI, Apache, PHP-FPM, or Laravel/Symfony crashes.
type PHPAnalysis struct {
	ErrorClass     string
	SummaryKo      string
	SummaryEn      string
	SuggestedFixKo string
	SuggestedFixEn string
	CulpritCode    *observerv1alpha1.CulpritCode
	IsFPM          bool
	AllocBytes     int64
	LimitBytes     int64
}

var (
	// Memory limit exhausted:
	// Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in /var/www/html/index.php on line 42
	phpMemoryLimitRegex = regexp.MustCompile(`Fatal error:\s*Allowed memory size of (\d+) bytes exhausted \(tried to allocate (\d+) bytes\) in (.+?) on line (\d+)`)

	// Maximum execution time:
	// Fatal error: Maximum execution time of 30 seconds exceeded in /var/www/html/worker.php on line 125
	phpMaxExecutionTimeRegex = regexp.MustCompile(`Fatal error:\s*Maximum execution time of (\d+) seconds exceeded in (.+?) on line (\d+)`)

	// Call to undefined function:
	// Fatal error: Uncaught Error: Call to undefined function curl_init() in /var/www/html/api.php on line 18
	phpUndefinedFunctionRegex = regexp.MustCompile(`Fatal error:\s*Uncaught Error:\s*Call to undefined function (\w+)\(\) in (.+?) on line (\d+)`)

	// Class not found:
	// Fatal error: Uncaught Error: Class "App\Services\PaymentService" not found in /var/www/html/bootstrap.php on line 55
	phpClassNotFoundRegex = regexp.MustCompile(`Fatal error:\s*Uncaught Error:\s*Class ["']([^"']+)["'] not found in (.+?) on line (\d+)`)

	// PHP-FPM max_children reached:
	// WARNING: [pool www] server reached max_children setting (10), consider raising it
	phpFPMChildrenExhaustedRegex = regexp.MustCompile(`WARNING:\s*\[pool ([^\]]+)\] server reached max_children setting \((\d+)\), consider raising it`)

	// PHP-FPM child signal exit (Segfault / Bus error in native extensions):
	// WARNING: [pool www] child 42 exited on signal 11 (SIGSEGV) after 12.345 seconds from start
	phpFPMChildSignalRegex = regexp.MustCompile(`WARNING:\s*\[pool ([^\]]+)\] child (\d+) exited on signal (11|7) \((SIGSEGV|SIGBUS)\)`)

	// PDO / Database Exception:
	// PDOException: SQLSTATE[HY000] [2002] Connection refused in /var/www/html/database.php on line 30
	phpPDORegex = regexp.MustCompile(`(?:PDOException|Illuminate\\Database\\QueryException):\s*SQLSTATE\[([A-Z0-9]+)\]\s*\[(\d+)\]\s*(.+?)(?: in (.+?) on line (\d+)|$)`)

	// Generic Uncaught Exception:
	// Fatal error: Uncaught Exception: User account suspended in /var/www/html/app.php on line 88
	phpUncaughtExceptionRegex = regexp.MustCompile(`Fatal error:\s*Uncaught ([a-zA-Z0-9_\\]+(?:Exception|Error)):\s*(.+?) in (.+?) on line (\d+)`)

	// Syntax / Parse Error:
	// Parse error: syntax error, unexpected token ";" in /var/www/html/test.php on line 12
	phpParseErrorRegex = regexp.MustCompile(`Parse error:\s*syntax error,\s*(.+?) in (.+?) on line (\d+)`)
)

// AnalyzePHPDeepCrash parses PHP error logs, extracting culprit files, lines, and root cause context.
func AnalyzePHPDeepCrash(logs string) *PHPAnalysis {
	if strings.TrimSpace(logs) == "" {
		return nil
	}

	// 1. Memory Limit Exhausted
	if m := phpMemoryLimitRegex.FindStringSubmatch(logs); len(m) >= 5 {
		limit, _ := strconv.ParseInt(m[1], 10, 64)
		alloc, _ := strconv.ParseInt(m[2], 10, 64)
		file := strings.TrimSpace(m[3])
		line, _ := strconv.Atoi(m[4])

		limitMB := limit / (1024 * 1024)
		return &PHPAnalysis{
			ErrorClass: "PHPMemoryLimitExceeded",
			SummaryKo:  fmt.Sprintf("PHP 메모리 제한(memory_limit = %dM) 초과로 스크립트 실행 중단 (추가 %d 바이트 할당 실패)", limitMB, alloc),
			SummaryEn:  fmt.Sprintf("PHP memory_limit (%dM) exhausted while trying to allocate %d bytes", limitMB, alloc),
			SuggestedFixKo: fmt.Sprintf("1) %s:%d 위치의 대용량 배열 생성 또는 반복문 메모리 누수를 점검하세요. 2) php.ini에서 'memory_limit = 256M' (또는 512M)로 상향하거나 ini_set('memory_limit', '512M')을 적용하세요.", file, line),
			SuggestedFixEn: fmt.Sprintf("1) Inspect large array allocations at %s:%d. 2) Increase 'memory_limit' in php.ini or via ini_set().", file, line),
			CulpritCode: &observerv1alpha1.CulpritCode{
				Language: "PHP",
				File:     file,
				Line:     line,
			},
			AllocBytes: alloc,
			LimitBytes: limit,
		}
	}

	// 2. Maximum Execution Time Exceeded
	if m := phpMaxExecutionTimeRegex.FindStringSubmatch(logs); len(m) >= 4 {
		secs, _ := strconv.Atoi(m[1])
		file := strings.TrimSpace(m[2])
		line, _ := strconv.Atoi(m[3])

		return &PHPAnalysis{
			ErrorClass: "PHPMaxExecutionTimeExceeded",
			SummaryKo:  fmt.Sprintf("PHP 스크립트 최대 실행 시간(max_execution_time = %d초) 초과로 강제 중단됨", secs),
			SummaryEn:  fmt.Sprintf("PHP maximum execution time of %d seconds exceeded", secs),
			SuggestedFixKo: fmt.Sprintf("1) %s:%d 위치의 무한 루프, 느린 외부 API 호출 또는 비효율적 DB 쿼리를 점검하세요. 2) 백그라운드 작업의 경우 'set_time_limit(0)' 또는 php.ini의 'max_execution_time'을 상향하세요.", file, line),
			SuggestedFixEn: fmt.Sprintf("1) Inspect infinite loops or blocking I/O at %s:%d. 2) Increase 'max_execution_time' in php.ini or use set_time_limit(0).", file, line),
			CulpritCode: &observerv1alpha1.CulpritCode{
				Language: "PHP",
				File:     file,
				Line:     line,
			},
		}
	}

	// 3. Call to Undefined Function
	if m := phpUndefinedFunctionRegex.FindStringSubmatch(logs); len(m) >= 4 {
		funcName := strings.TrimSpace(m[1])
		file := strings.TrimSpace(m[2])
		line, _ := strconv.Atoi(m[3])

		return &PHPAnalysis{
			ErrorClass: "PHPUndefinedFunction",
			SummaryKo:  fmt.Sprintf("정의되지 않은 PHP 함수 '%s()' 호출로 치명적 오류 발생 (누락된 PHP 익스텐션 또는 오탈자)", funcName),
			SummaryEn:  fmt.Sprintf("Call to undefined function '%s()' (missing PHP extension or typo)", funcName),
			SuggestedFixKo: fmt.Sprintf("1) %s:%d에서 호출한 '%s()'에 필요한 PHP 확장 모듈(예: ext-%s, mbstring, curl, pdo, gd)이 Dockerfile에 설치되어 있는지 확인하세요 (예: 'docker-php-ext-install %s').", file, line, funcName, funcName, funcName),
			SuggestedFixEn: fmt.Sprintf("1) Ensure the required PHP extension for '%s()' is installed in Dockerfile (e.g., 'docker-php-ext-install %s'). Check %s:%d.", funcName, funcName, file, line),
			CulpritCode: &observerv1alpha1.CulpritCode{
				Language: "PHP",
				File:     file,
				Line:     line,
				Function: funcName,
			},
		}
	}

	// 4. Class Not Found
	if m := phpClassNotFoundRegex.FindStringSubmatch(logs); len(m) >= 4 {
		className := strings.TrimSpace(m[1])
		file := strings.TrimSpace(m[2])
		line, _ := strconv.Atoi(m[3])

		return &PHPAnalysis{
			ErrorClass: "PHPClassNotFound",
			SummaryKo:  fmt.Sprintf("PHP 클래스 '%s'를 찾을 수 없음 (Composer 오토로드 누락 또는 네임스페이스 불일치)", className),
			SummaryEn:  fmt.Sprintf("PHP Class '%s' not found (missing Composer autoloader or namespace mismatch)", className),
			SuggestedFixKo: fmt.Sprintf("1) %s:%d 위치에서 'require_once __DIR__ . '/vendor/autoload.php';'가 로드되었는지 확인하세요. 2) 'composer dump-autoload -o'를 실행하여 클래스맵을 갱신하세요.", file, line),
			SuggestedFixEn: fmt.Sprintf("1) Verify Composer autoloader is included at %s:%d. 2) Run 'composer dump-autoload -o' to regenerate class mappings.", file, line),
			CulpritCode: &observerv1alpha1.CulpritCode{
				Language: "PHP",
				File:     file,
				Line:     line,
			},
		}
	}

	// 5. PHP-FPM max_children Reached
	if m := phpFPMChildrenExhaustedRegex.FindStringSubmatch(logs); len(m) >= 3 {
		poolName := m[1]
		maxChildren, _ := strconv.Atoi(m[2])

		return &PHPAnalysis{
			ErrorClass: "PHPFPMChildrenExhausted",
			SummaryKo:  fmt.Sprintf("PHP-FPM 풀 [%s]의 최대 워커 프로세스 수(pm.max_children = %d) 고갈로 신규 요청 지연 및 502/504 발생", poolName, maxChildren),
			SummaryEn:  fmt.Sprintf("PHP-FPM pool [%s] server reached max_children setting (%d), blocking incoming web requests", poolName, maxChildren),
			SuggestedFixKo: "1) 파드 메모리 사양에 맞추어 php-fpm.d/www.conf의 'pm.max_children'을 증설하세요 (워커당 약 30~50MB 산정). 2) 롱런 프로세스 및 느린 DB 쿼리를 최적화하여 워커 점유 시간을 단축하세요.",
			SuggestedFixEn: "1) Increase 'pm.max_children' in php-fpm.d/www.conf according to pod memory limits. 2) Optimize slow queries to release workers faster.",
			IsFPM:          true,
		}
	}

	// 6. PHP-FPM Child Signal Exit (Segfault / Bus error in native extensions)
	if m := phpFPMChildSignalRegex.FindStringSubmatch(logs); len(m) >= 4 {
		poolName := m[1]
		sigName := m[3]

		return &PHPAnalysis{
			ErrorClass: "PHPFPMChildSignalCrash",
			SummaryKo:  fmt.Sprintf("PHP-FPM 풀 [%s] 워커 프로세스가 치명적 시그널 %s로 인해 충돌 종료됨 (네이티브 C 익스텐션 메모리 침범)", poolName, sigName),
			SummaryEn:  fmt.Sprintf("PHP-FPM pool [%s] child crashed on signal %s (native C extension memory fault)", poolName, sigName),
			SuggestedFixKo: "1) 설치된 PHP C 확장 모듈(Imagick, OPcache, Xdebug, gRPC)의 버전 호환성을 점검하세요. 2) core dump를 활성화하거나 strace/gdb로 세그폴트 발생 프레임을 추적하세요.",
			SuggestedFixEn: "1) Check version compatibility of PHP native extensions (Imagick, OPcache, Xdebug). 2) Inspect core dumps for segfault stack trace.",
			IsFPM:          true,
		}
	}

	// 7. PDO / Database Exception
	if m := phpPDORegex.FindStringSubmatch(logs); len(m) >= 4 {
		sqlState := m[1]
		errNo := m[2]
		errMsg := strings.TrimSpace(m[3])
		file := ""
		line := 0
		if len(m) >= 6 && m[4] != "" {
			file = strings.TrimSpace(m[4])
			line, _ = strconv.Atoi(m[5])
		}

		culprit := (*observerv1alpha1.CulpritCode)(nil)
		if file != "" {
			culprit = &observerv1alpha1.CulpritCode{
				Language: "PHP",
				File:     file,
				Line:     line,
			}
		}

		return &PHPAnalysis{
			ErrorClass: "PHPPDOException",
			SummaryKo:  fmt.Sprintf("PHP PDO 데이터베이스 오류 발생 [SQLSTATE %s, Errno %s]: %s", sqlState, errNo, errMsg),
			SummaryEn:  fmt.Sprintf("PHP PDO database error [SQLSTATE %s, Errno %s]: %s", sqlState, errNo, errMsg),
			SuggestedFixKo: "1) 데이터베이스 호스트명(K8s Service DNS), 포트, 사용자 자격 증명 환경변수를 점검하세요. 2) PDO 연결 타임아웃(PDO::ATTR_TIMEOUT) 및 재시도 로직을 적용하세요.",
			SuggestedFixEn: "1) Verify DB connection credentials, host DNS, and port. 2) Set PDO::ATTR_TIMEOUT and implement connection retries.",
			CulpritCode:    culprit,
		}
	}

	// 8. Generic Uncaught PHP Exception
	if m := phpUncaughtExceptionRegex.FindStringSubmatch(logs); len(m) >= 5 {
		excClass := strings.TrimSpace(m[1])
		excMsg := strings.TrimSpace(m[2])
		file := strings.TrimSpace(m[3])
		line, _ := strconv.Atoi(m[4])

		return &PHPAnalysis{
			ErrorClass: "PHPUnhandledException",
			SummaryKo:  fmt.Sprintf("PHP 미처리 예외(%s) 발생: %s", excClass, excMsg),
			SummaryEn:  fmt.Sprintf("PHP unhandled exception (%s): %s", excClass, excMsg),
			SuggestedFixKo: fmt.Sprintf("1) %s:%d 위치의 예외 발생 원인을 확인하고 try-catch 블록으로 예외 처리를 추가하세요.", file, line),
			SuggestedFixEn: fmt.Sprintf("1) Add try-catch error handling at %s:%d.", file, line),
			CulpritCode: &observerv1alpha1.CulpritCode{
				Language: "PHP",
				File:     file,
				Line:     line,
			},
		}
	}

	// 9. Parse / Syntax Error
	if m := phpParseErrorRegex.FindStringSubmatch(logs); len(m) >= 4 {
		syntaxDetail := strings.TrimSpace(m[1])
		file := strings.TrimSpace(m[2])
		line, _ := strconv.Atoi(m[3])

		return &PHPAnalysis{
			ErrorClass: "PHPSyntaxError",
			SummaryKo:  fmt.Sprintf("PHP 구문 오류(Syntax Error)로 실행 실패: %s", syntaxDetail),
			SummaryEn:  fmt.Sprintf("PHP syntax error: %s", syntaxDetail),
			SuggestedFixKo: fmt.Sprintf("1) %s:%d 위치의 문법 오류(세미콜론 누락, 괄호 불일치 등)를 수정하세요. 2) 빌드 시 'php -l <file>'로 린트 검증을 수행하세요.", file, line),
			SuggestedFixEn: fmt.Sprintf("1) Fix syntax error at %s:%d. 2) Run 'php -l' during CI build to validate syntax.", file, line),
			CulpritCode: &observerv1alpha1.CulpritCode{
				Language: "PHP",
				File:     file,
				Line:     line,
			},
		}
	}

	return nil
}
