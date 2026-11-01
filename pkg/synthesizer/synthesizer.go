package synthesizer

import (
	"context"
	"fmt"
	"strings"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
)

const EngineIdentifier = "rule-synthesizer"

// Synthesizer synthesizes factual causal chains and actionable recommendations
// using verified execution evidence and domain-specific incident rules.
type Synthesizer struct{}

func NewSynthesizer() *Synthesizer {
	return &Synthesizer{}
}

func (s *Synthesizer) Synthesize(ctx context.Context, incident IncidentContext) (*InsightResult, error) {
	reqLang := strings.ToLower(strings.TrimSpace(incident.Language))
	targetLang := "ko" // Default language: Korean
	actualLangRecord := "ko"

	if reqLang == "en" {
		targetLang = "en"
		actualLangRecord = "en"
	} else if reqLang != "" && reqLang != "ko" {
		// Requested unsupported language: record fallback
		targetLang = "ko"
		actualLangRecord = fmt.Sprintf("ko (fallback from %s)", reqLang)
	}

	chain := buildRootCauseChain(incident, targetLang)
	inferredContext := buildInferredContext(incident, targetLang)
	suggestedFix := buildSuggestedFix(incident, targetLang)

	return &InsightResult{
		Engine:          EngineIdentifier,
		Analyzed:        true,
		Language:        actualLangRecord,
		Confidence:      incident.Confidence,
		InferredContext: inferredContext,
		SuggestedFix:    suggestedFix,
		RootCauseChain:  chain,
	}, nil
}

func buildRootCauseChain(inc IncidentContext, lang string) []observerv1alpha1.ChainStep {
	var steps []string
	exitCodeStr := "Unknown"
	if inc.ExitCode != nil {
		exitCodeStr = fmt.Sprintf("%d", *inc.ExitCode)
	}

	if lang == "ko" {
		switch inc.RootCause {
		case "OOMKilled", "ProbableOOMKilled":
			steps = append(steps, "컨테이너 내 프로세스의 메모리 사용량이 증가함")
			steps = append(steps, "설정된 cgroup 메모리 한도(Memory Limit)에 도달함")
			steps = append(steps, fmt.Sprintf("Linux 커널 OOM Killer에 의해 프로세스가 SIGKILL(Exit code %s)로 강제 종료됨", exitCodeStr))
			steps = append(steps, "Kubelet이 종료 상태(OOMKilled)를 감지하고 파드 재시작 정책에 따라 컨테이너를 재시작함")
		case "LivenessProbeFailure":
			steps = append(steps, "애플리케이션이 지정된 헬스체크 엔드포인트 응답을 시간 내에 반환하지 못함")
			steps = append(steps, "Kubelet의 Liveness Probe 연속 실패 횟수가 failureThreshold 한도를 초과함")
			steps = append(steps, fmt.Sprintf("Kubelet이 비정상 컨테이너로 판정하여 프로세스를 종료(Exit code %s) 및 재기동함", exitCodeStr))
		case "GoDeadlock":
			steps = append(steps, "Go 고루틴 간 채널 또는 뮤텍스 동기화 대기가 발생함")
			steps = append(steps, "실행 가능한 고루틴이 모두 대기 상태에 빠져 런큐가 정지됨")
			steps = append(steps, "Go 런타임이 'all goroutines are asleep - deadlock!' 치명적 오류를 출력하고 프로세스를 중단함")
		case "GoPanic":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				steps = append(steps, fmt.Sprintf("애플리케이션 코드 %s:%d 위치에서 런타임 패닉(Panic)이 발생함", inc.CulpritCode.File, inc.CulpritCode.Line))
			} else {
				steps = append(steps, "애플리케이션 내부에서 복구되지 않은 런타임 패닉(Panic)이 발생함")
			}
			steps = append(steps, "상위 핸들러에서 recover()되지 않아 스택 언와인딩이 최상위까지 전파됨")
			steps = append(steps, fmt.Sprintf("Go 프로세스가 표준 에러에 스택트레이스를 출력하고 Exit code %s로 종료됨", exitCodeStr))
		case "DotNetNullReference":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				steps = append(steps, fmt.Sprintf("%s:%d (%s)에서 초기화되지 않은 Null 객체 참조가 발생함", inc.CulpritCode.File, inc.CulpritCode.Line, inc.CulpritCode.Function))
			} else {
				steps = append(steps, ".NET 애플리케이션에서 System.NullReferenceException 예외가 발생함")
			}
			steps = append(steps, "예외가 처리되지 않아 CLR 런타임 프로세스가 종료됨")
		case "JVMHeapOOM":
			steps = append(steps, "JVM 힙 메모리(-Xmx) 한도에 도달함")
			steps = append(steps, "가비지 컬렉터(GC)가 추가 메모리 공간을 확보하지 못함")
			steps = append(steps, "java.lang.OutOfMemoryError: Java heap space 에러가 발생하며 JVM 프로세스가 종료됨")
		default:
			steps = append(steps, fmt.Sprintf("컨테이너 상태 이상이 감지됨 (RootCause: %s, ExitCode: %s)", inc.RootCause, exitCodeStr))
			if len(inc.MatchedEvents) > 0 {
				steps = append(steps, fmt.Sprintf("관련 쿠버네티스 이벤트 확인: %s", inc.MatchedEvents[0]))
			}
			steps = append(steps, "프로세스 종료 후 Kubelet에 의해 컨테이너가 재시작됨")
		}
	} else {
		// English default
		switch inc.RootCause {
		case "OOMKilled", "ProbableOOMKilled":
			steps = append(steps, "Container memory usage increased steadily")
			steps = append(steps, "Exceeded configured cgroup memory limit")
			steps = append(steps, fmt.Sprintf("Linux kernel OOM Killer terminated the process with SIGKILL (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet observed OOMKilled state and restarted the container per policy")
		case "LivenessProbeFailure":
			steps = append(steps, "Application failed to respond to configured liveness probe within timeout")
			steps = append(steps, "Consecutive probe failures exceeded failureThreshold")
			steps = append(steps, fmt.Sprintf("Kubelet restarted the unresponsive container (Exit code %s)", exitCodeStr))
		case "GoDeadlock":
			steps = append(steps, "Mutual channel or mutex lock contention occurred across all active goroutines")
			steps = append(steps, "No runnable goroutines remained on the Go runtime runqueue")
			steps = append(steps, "Go runtime fatal error triggered: 'all goroutines are asleep - deadlock!'")
		case "GoPanic":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				steps = append(steps, fmt.Sprintf("Runtime panic encountered at %s:%d", inc.CulpritCode.File, inc.CulpritCode.Line))
			} else {
				steps = append(steps, "Unhandled runtime panic occurred in application code")
			}
			steps = append(steps, "Stack unwinding reached top-level without recover()")
			steps = append(steps, fmt.Sprintf("Process exited with code %s", exitCodeStr))
		case "DotNetNullReference":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				steps = append(steps, fmt.Sprintf("Null object dereference at %s:%d (%s)", inc.CulpritCode.File, inc.CulpritCode.Line, inc.CulpritCode.Function))
			} else {
				steps = append(steps, "System.NullReferenceException thrown in .NET runtime")
			}
			steps = append(steps, "Unhandled exception caused CLR runtime termination")
		case "JVMHeapOOM":
			steps = append(steps, "JVM heap limit (-Xmx) was reached")
			steps = append(steps, "Garbage collection failed to reclaim sufficient memory")
			steps = append(steps, "java.lang.OutOfMemoryError: Java heap space thrown; JVM exited")
		default:
			steps = append(steps, fmt.Sprintf("Container termination observed (RootCause: %s, ExitCode: %s)", inc.RootCause, exitCodeStr))
			if len(inc.MatchedEvents) > 0 {
				steps = append(steps, fmt.Sprintf("Correlated K8s Event: %s", inc.MatchedEvents[0]))
			}
			steps = append(steps, "Container exited and was restarted by Kubelet")
		}
	}

	var res []observerv1alpha1.ChainStep
	for i, s := range steps {
		res = append(res, observerv1alpha1.ChainStep{
			Step:        i + 1,
			Description: s,
		})
	}
	return res
}

func buildInferredContext(inc IncidentContext, lang string) string {
	culpritStr := ""
	if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
		if inc.CulpritCode.Line > 0 {
			culpritStr = fmt.Sprintf(" [%s:%d]", inc.CulpritCode.File, inc.CulpritCode.Line)
		} else {
			culpritStr = fmt.Sprintf(" [%s]", inc.CulpritCode.File)
		}
	}

	if lang == "ko" {
		switch inc.RootCause {
		case "OOMKilled", "ProbableOOMKilled":
			return "컨테이너의 실제 메모리 사용량이 cgroup에 설정된 한도(Limit)를 초과하여 리눅스 커널 OOM Killer에 의해 프로세스가 강제 사살되었습니다."
		case "LivenessProbeFailure":
			return "애플리케이션이 Liveness Probe 검사에 제한 시간 내에 응답하지 못하여 Kubelet에 의해 비정상으로 판정되고 재기동되었습니다."
		case "GoPanic":
			return fmt.Sprintf("Go 애플리케이션 소스코드에서 미처리 런타임 패닉(Panic)이 발생하여 프로세스가 충돌했습니다%s.", culpritStr)
		case "GoDeadlock":
			return "Go 런타임에서 모든 고루틴이 대기 상태에 빠진 교착 상태(Deadlock)가 발생하여 프로세스가 강제 중단되었습니다."
		case "DotNetNullReference":
			return fmt.Sprintf(".NET 애플리케이션에서 초기화되지 않은 객체 참조(NullReferenceException)가 발생했습니다%s.", culpritStr)
		case "DotNetUnhandledException":
			return fmt.Sprintf(".NET 애플리케이션에서 처리되지 않은 런타임 예외가 발생하여 프로세스가 중단되었습니다%s.", culpritStr)
		case "PythonUnhandledException":
			return fmt.Sprintf("파이썬 스크립트 실행 중 처리되지 않은 예외(Unhandled Exception)가 발생하여 종료되었습니다%s.", culpritStr)
		case "JVMHeapOOM":
			return "Java 가상 머신(JVM)의 힙 메모리가 소진되어 OutOfMemoryError가 발생했습니다."
		default:
			return fmt.Sprintf("컨테이너가 %s 원인으로 비정상 종료되었습니다%s.", inc.RootCause, culpritStr)
		}
	}

	// English default
	switch inc.RootCause {
	case "OOMKilled", "ProbableOOMKilled":
		return "Container memory consumption exceeded the configured cgroup limit and was terminated by the Linux kernel OOM Killer."
	case "LivenessProbeFailure":
		return "The application failed to respond to configured liveness probes in time and was restarted by Kubelet."
	case "GoPanic":
		return fmt.Sprintf("Unhandled Go runtime panic caused application crash%s.", culpritStr)
	case "GoDeadlock":
		return "All active goroutines entered a waiting state (Deadlock), halting the Go runtime."
	case "DotNetNullReference":
		return fmt.Sprintf("Uninitialized object reference (NullReferenceException) encountered in .NET runtime%s.", culpritStr)
	case "DotNetUnhandledException":
		return fmt.Sprintf("Unhandled .NET exception terminated the process%s.", culpritStr)
	case "PythonUnhandledException":
		return fmt.Sprintf("Unhandled Python exception caused process termination%s.", culpritStr)
	case "JVMHeapOOM":
		return "JVM exhausted allocated heap memory (-Xmx), resulting in OutOfMemoryError."
	default:
		return fmt.Sprintf("Container terminated due to %s%s.", inc.RootCause, culpritStr)
	}
}

func buildSuggestedFix(inc IncidentContext, lang string) string {
	if lang == "ko" {
		switch inc.RootCause {
		case "OOMKilled", "ProbableOOMKilled":
			return "1) 파드 스펙의 메모리 한도(resources.limits.memory)를 증설하세요. 2) 애플리케이션의 메모리 누수 여부를 프로파일링하세요."
		case "LivenessProbeFailure":
			return "1) livenessProbe의 timeoutSeconds 및 failureThreshold를 조정하세요. 2) 헬스체크 엔드포인트가 무거운 외부 의존성 작업에 블로킹되지 않도록 점검하세요."
		case "GoPanic":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				return fmt.Sprintf("해당 소스코드(%s:%d)에서 Nil 포인터 체크를 보강하거나 defer recover() 함수로 예외를 핸들링하세요.", inc.CulpritCode.File, inc.CulpritCode.Line)
			}
			return "최상위 고루틴에 defer recover() 블록을 구현하여 패닉 발생 시 프로세스 크래시를 방지하세요."
		case "DotNetNullReference":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				return fmt.Sprintf("%s:%d의 참조 대상 객체가 null인지 확인하고, C#의 '?.' 연산자 등을 적용하세요.", inc.CulpritCode.File, inc.CulpritCode.Line)
			}
			return "객체 인스턴스화 여부를 점검하고 전역 예외 처리 미들웨어를 보강하세요."
		case "JVMHeapOOM":
			return "1) JVM -Xmx 힙 한도를 증설하거나 파드 메모리 제한을 늘리세요. 2) -XX:+HeapDumpOnOutOfMemoryError 옵션으로 힙 덤프를 추출하여 메모리 점유 객체를 분석하세요."
		default:
			return "직전 컨테이너 로그 및 종료 코드를 확인하여 애플리케이션 설정 및 파드 리소스 사양을 점검하세요."
		}
	}

	// English default
	switch inc.RootCause {
	case "OOMKilled", "ProbableOOMKilled":
		return "1) Increase pod memory limit (resources.limits.memory). 2) Profile application memory allocations to eliminate leaks."
	case "LivenessProbeFailure":
		return "1) Adjust probe timeoutSeconds and failureThreshold. 2) Ensure health check endpoint does not block on slow downstream dependencies."
	case "GoPanic":
		if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
			return fmt.Sprintf("Inspect %s:%d for nil pointer or slice index out-of-range, and guard with nil checks or defer recover().", inc.CulpritCode.File, inc.CulpritCode.Line)
		}
		return "Implement top-level defer recover() to prevent unexpected panics from terminating the process."
	case "DotNetNullReference":
		if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
			return fmt.Sprintf("Verify object initialization at %s:%d or apply null-conditional operator (?. / ??).", inc.CulpritCode.File, inc.CulpritCode.Line)
		}
		return "Check dependency injection registration and configure global exception handling middleware."
	case "JVMHeapOOM":
		return "1) Increase -Xmx heap limit or pod memory limit. 2) Enable -XX:+HeapDumpOnOutOfMemoryError to inspect memory leak candidates."
	default:
		return "Inspect previous container logs and verify pod resource limits and application configurations."
	}
}
