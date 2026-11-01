package knowledge

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
)

// JavaFrame represents a single line in a Java stack trace.
type JavaFrame struct {
	FullClass string
	Method    string
	File      string
	Line      int
	IsUser    bool
}

// JavaDeepAnalysis holds the deep diagnostic findings extracted from Java/Spring crash logs.
type JavaDeepAnalysis struct {
	TopExceptionClass    string
	TopExceptionMessage  string
	RootExceptionClass   string
	RootExceptionMessage string
	IsUnwrapped          bool
	CausedByChain        []string
	Framework            string
	CulpritCode          *observerv1alpha1.CulpritCode
	CircularBeans        []string
	SuggestedFix         string
	SuggestedFixKo       string
	SummaryKo            string
	SummaryEn            string
	NativeCrashFrame     string
	NativeCrashLib       string
}

var (
	javaTopExcRegex    = regexp.MustCompile(`(?m)^([a-zA-Z0-9_\.\$]+(?:Exception|Error|Throwable))(?::\s*(.*))?$`)
	javaCausedByRegex  = regexp.MustCompile(`(?m)^Caused by:\s*([a-zA-Z0-9_\.\$]+(?:Exception|Error|Throwable))(?::\s*(.*))?$`)
	javaStackFrameRegex = regexp.MustCompile(`^\s*at\s+([a-zA-Z0-9_\.$]+)\.([a-zA-Z0-9_$<>]+\b)\((?:([a-zA-Z0-9_\.]+\.java):(\d+)|Native Method|Unknown Source)\)`)
	javaCircularRegex  = regexp.MustCompile(`┌─────┐\r?\n(?:[│\s\^↑↓\|]+([a-zA-Z0-9_]+)[^\r\n]*\r?\n)+└─────┘`)
	javaBeanCycleAlt   = regexp.MustCompile(`The dependencies of some of the beans in the application context form a cycle:\r?\n\s*┌─────┐\r?\n\s*\|\s*([a-zA-Z0-9_]+)`)
	javaHikariTimeout  = regexp.MustCompile(`HikariPool-(\d+) - Connection is not available, request timed out after (\d+)ms`)
	javaHsErrRegex     = regexp.MustCompile(`# Problematic frame:\r?\n#\s*([CjV])\s+\[([^\+\]]+)(?:\+([^\]]+))?\]`)
)

// AnalyzeJavaDeepCrash performs multi-tiered "Caused by:" unwrapping and Spring/JPA/Hikari inspection.
func AnalyzeJavaDeepCrash(logs string) *JavaDeepAnalysis {
	if !strings.Contains(logs, "Exception") &&
		!strings.Contains(logs, "Error") &&
		!strings.Contains(logs, "# Problematic frame:") &&
		!strings.Contains(logs, "\tat ") {
		return nil
	}

	analysis := &JavaDeepAnalysis{}

	// 1. Check for JVM Native Crash Dump (hs_err_pid)
	if hsMatch := javaHsErrRegex.FindStringSubmatch(logs); len(hsMatch) >= 3 {
		frameType := hsMatch[1]
		libName := hsMatch[2]
		analysis.NativeCrashFrame = frameType
		analysis.NativeCrashLib = libName
		analysis.TopExceptionClass = "JVMNativeCrashDump"
		analysis.RootExceptionClass = "JVMNativeCrashDump"
		if frameType == "C" {
			analysis.SummaryKo = fmt.Sprintf("JVM 네이티브 JNI 라이브러리 충돌 (%s)", libName)
			analysis.SuggestedFixKo = fmt.Sprintf("JNI 바인딩 라이브러리 '%s'의 버전 호환성(glibc/musl) 및 메모리 누수를 점검하거나 드라이버 버전을 업데이트하십시오.", libName)
			analysis.SummaryEn = fmt.Sprintf("Fatal JVM native crash in JNI library (%s)", libName)
			analysis.SuggestedFix = fmt.Sprintf("Verify ABI compatibility (glibc/musl) and memory integrity of JNI native library '%s'.", libName)
		} else {
			analysis.SummaryKo = fmt.Sprintf("JVM 내부 런타임/컴파일러 충돌 (HotSpot %s)", libName)
			analysis.SuggestedFixKo = "JVM JDK 배포판 버그일 가능성이 높습니다. 최신 JDK 패치 릴리스로 베이스 이미지를 업데이트하십시오."
			analysis.SummaryEn = fmt.Sprintf("Internal HotSpot JVM crash (%s)", libName)
			analysis.SuggestedFix = "Update base container image to the latest JDK maintenance release to resolve HotSpot engine bug."
		}
		return analysis
	}

	// 2. Parse Top-level Exception
	topMatches := javaTopExcRegex.FindAllStringSubmatch(logs, -1)
	if len(topMatches) > 0 {
		analysis.TopExceptionClass = topMatches[0][1]
		if len(topMatches[0]) > 2 {
			analysis.TopExceptionMessage = strings.TrimSpace(topMatches[0][2])
		}
		analysis.RootExceptionClass = analysis.TopExceptionClass
		analysis.RootExceptionMessage = analysis.TopExceptionMessage
	}

	// 3. Recursive "Caused by:" Chain Unwrapping
	causedMatches := javaCausedByRegex.FindAllStringSubmatch(logs, -1)
	if len(causedMatches) > 0 {
		analysis.IsUnwrapped = true
		for _, cm := range causedMatches {
			exc := cm[1]
			analysis.CausedByChain = append(analysis.CausedByChain, exc)
		}
		// The innermost exception is the true root cause
		innermost := causedMatches[len(causedMatches)-1]
		analysis.RootExceptionClass = innermost[1]
		if len(innermost) > 2 {
			analysis.RootExceptionMessage = strings.TrimSpace(innermost[2])
		}
	}

	// 4. Parse Stack Frames and Pinpoint User Business Code
	lines := strings.Split(logs, "\n")
	var frames []JavaFrame
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if m := javaStackFrameRegex.FindStringSubmatch(trimmed); len(m) >= 3 {
			fullClass := m[1]
			method := m[2]
			file := ""
			lineNum := 0
			if len(m) >= 5 && m[3] != "" {
				file = m[3]
				lineNum, _ = strconv.Atoi(m[4])
			}
			isUser := isJavaUserCode(fullClass)
			frames = append(frames, JavaFrame{
				FullClass: fullClass,
				Method:    method,
				File:      file,
				Line:      lineNum,
				IsUser:    isUser,
			})
		}
	}

	// Find the deepest user frame in the stack trace
	for _, f := range frames {
		if f.IsUser && f.Line > 0 {
			analysis.CulpritCode = &observerv1alpha1.CulpritCode{
				Language:  "Java",
				Framework: "Spring",
				File:      f.File,
				Line:      f.Line,
				Function:  f.FullClass + "." + f.Method,
			}
			break
		}
	}

	// 5. Spring / JPA / Hikari Domain Rules
	detectJavaDomainRules(logs, analysis)

	return analysis
}

func isJavaUserCode(fullClass string) bool {
	// Filter out common frameworks, JDK, and third-party libraries
	prefixes := []string{
		"java.", "javax.", "jakarta.", "sun.", "jdk.",
		"org.springframework.", "org.apache.", "com.zaxxer.",
		"io.netty.", "ch.qos.logback.", "org.slf4j.", "org.hibernate.",
		"com.mysql.", "org.postgresql.", "org.mongodb.", "redis.clients.",
		"io.lettuce.", "com.fasterxml.", "net.bytebuddy.", "org.mockito.",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(fullClass, p) {
			return false
		}
	}
	return true
}

func detectJavaDomainRules(logs string, analysis *JavaDeepAnalysis) {
	lowerLogs := strings.ToLower(logs)

	// Framework detection
	if strings.Contains(lowerLogs, "org.springframework") {
		analysis.Framework = "Spring Boot"
	} else if strings.Contains(lowerLogs, "quarkus") {
		analysis.Framework = "Quarkus"
	} else if strings.Contains(lowerLogs, "io.micronaut") {
		analysis.Framework = "Micronaut"
	}

	// 1. Spring Circular Dependency
	if strings.Contains(logs, "form a cycle:") || strings.Contains(logs, "circular dependency") {
		analysis.SummaryKo = "Spring Boot 빈 상호 순환 참조(Circular Dependency)로 인한 컨텍스트 초기화 실패"
		analysis.SuggestedFixKo = "1) 상호 의존하는 빈 주입 지점에 '@Lazy' 어노테이션을 부여하거나, 2) 공통 로직을 제3의 서비스 빈으로 분리하거나, 3) 임시로 application.yml에 'spring.main.allow-circular-references: true'를 활성화하십시오."
		analysis.SummaryEn = "Spring Boot circular bean dependency preventing ApplicationContext initialization"
		analysis.SuggestedFix = "1) Add '@Lazy' on the injected dependency, 2) refactor shared methods into a separate service, or 3) temporarily set 'spring.main.allow-circular-references: true' in application.yml."
		return
	}

	// 2. HikariCP Connection Timeout
	if hMatch := javaHikariTimeout.FindStringSubmatch(logs); len(hMatch) >= 3 {
		timeoutMs := hMatch[2]
		analysis.SummaryKo = fmt.Sprintf("HikariCP 커넥션 풀 고갈: DB 연결 획득 실패 (타임아웃 %sms)", timeoutMs)
		analysis.SuggestedFixKo = fmt.Sprintf("1) application.yml의 'spring.datasource.hikari.maximum-pool-size' 증설을 검토하고, 2) 'leak-detection-threshold: 2000'을 추가하여 커넥션 누수를 추적하십시오.", )
		analysis.SummaryEn = fmt.Sprintf("HikariCP connection pool exhausted: failed to obtain DB connection within %sms timeout", timeoutMs)
		analysis.SuggestedFix = "1) Review spring.datasource.hikari.maximum-pool-size, 2) enable 'spring.datasource.hikari.leak-detection-threshold=2000' to track unclosed connections, and 3) optimize slow SQL queries."
		return
	}

	// 3. Hibernate LazyInitializationException
	if strings.Contains(analysis.RootExceptionClass, "LazyInitializationException") {
		analysis.SummaryKo = "Hibernate LazyInitializationException: 영속성 컨텍스트(Session) 종료 후 지연 로딩 접근"
		analysis.SuggestedFixKo = "1) JPQL/Repository 쿼리에 'JOIN FETCH'를 적용하여 연관 엔티티를 즉시 조회하거나, 2) '@EntityGraph'를 사용하거나, 3) 트랜잭션 범위('@Transactional') 내에서 연관 필드를 참조하십시오."
		analysis.SummaryEn = "Hibernate LazyInitializationException: failed to lazily initialize a collection or proxy without active session"
		analysis.SuggestedFix = "1) Use 'JOIN FETCH' in JPQL queries, 2) apply '@EntityGraph', or 3) ensure property access occurs within an active '@Transactional' method scope."
		return
	}

	// 4. PKIX SSL Handshake
	if strings.Contains(logs, "SSLHandshakeException") && strings.Contains(logs, "PKIX path building failed") {
		analysis.SummaryKo = "JVM SSL/TLS 핸드셰이크 실패: 신뢰할 수 없는 사설 CA 인증서 (PKIX path building failed)"
		analysis.SuggestedFixKo = "사내 프라이빗 CA 또는 자체 서명 인증서(.crt/.pem)를 컨테이너 빌드 시 'keytool -importcert -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit' 명령어로 신뢰 저장소에 임포트하십시오."
		analysis.SummaryEn = "JVM SSL Handshake error: untrusted CA certificate (PKIX path building failed)"
		analysis.SuggestedFix = "Import internal private root CA certificate into JVM keystore ($JAVA_HOME/lib/security/cacerts) using 'keytool -importcert'."
		return
	}

	// 5. Hibernate TransientPropertyValueException
	if strings.Contains(analysis.RootExceptionClass, "TransientPropertyValueException") ||
		strings.Contains(logs, "object references an unsaved transient instance") {
		analysis.SummaryKo = "JPA TransientPropertyValueException: 영속화되지 않은 자식 엔티티 참조"
		analysis.SuggestedFixKo = "엔티티 관계 어노테이션에 'cascade = CascadeType.ALL' 또는 'CascadeType.PERSIST'를 추가하거나, 자식 엔티티를 부모보다 먼저 repository.save() 하십시오."
		analysis.SummaryEn = "JPA TransientPropertyValueException: object references an unsaved transient instance"
		analysis.SuggestedFix = "Add 'cascade = CascadeType.ALL' or 'CascadeType.PERSIST' to relation mapping, or persist the transient child entity first."
		return
	}
}
