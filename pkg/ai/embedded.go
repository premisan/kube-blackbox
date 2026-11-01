package ai

import (
	"context"
	"fmt"
	"strings"

	observerv1alpha1 "github.com/premisan/kube-pinger/api/v1alpha1"
)

// EmbeddedEngine performs deterministic semantic synthesis and multi-language explanation
// without requiring an external AI server or GPU.
type EmbeddedEngine struct {
	modelName string
}

func NewEmbeddedEngine(modelName string) *EmbeddedEngine {
	if modelName == "" {
		modelName = "embedded-semantic-analyzer"
	}
	return &EmbeddedEngine{modelName: modelName}
}

func (e *EmbeddedEngine) Analyze(ctx context.Context, incident IncidentContext) (*AIInsightResult, error) {
	lang := strings.ToLower(strings.TrimSpace(incident.Language))
	if lang == "" {
		lang = "en"
	}

	chain := buildRootCauseChain(incident, lang)
	inferredContext := buildInferredContext(incident, lang)
	suggestedFix := buildSuggestedFix(incident, lang)

	return &AIInsightResult{
		Model:           e.modelName,
		Analyzed:        true,
		Language:        lang,
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
			steps = append(steps, "컨테이너 내 프로세스의 메모리 할당량이 지속적으로 증가함")
			steps = append(steps, "cgroup 메모리 한도(Memory Limit)에 도달하여 추가 페이지 할당 실패")
			steps = append(steps, fmt.Sprintf("Linux 커널 OOM Killer가 동작하여 SIGKILL(Exit code %s)로 프로세스를 강제 종료함", exitCodeStr))
			steps = append(steps, "Kubelet이 종료 상태를 감지하고 restartPolicy에 따라 파드 컨테이너를 재시작함")
		case "LivenessProbeFailure":
			steps = append(steps, "애플리케이션 처리 지연, 교착 상태(Deadlock) 또는 커넥션 풀 고갈 발생")
			steps = append(steps, "Liveness Probe 엔드포인트 응답이 timeoutSeconds 내에 도착하지 않음")
			steps = append(steps, "Kubelet이 연속 실패 횟수(failureThreshold)를 초과한 것으로 판정")
			steps = append(steps, fmt.Sprintf("Kubelet이 활성도 실패 파드를 비정상으로 간주하고 프로세스를 종료(Exit code %s) 및 재기동함", exitCodeStr))
		case "GoDeadlock":
			steps = append(steps, "고루틴 간 상호 대기 상태(채널 또는 뮤텍스 Lock 경쟁) 발생")
			steps = append(steps, "실행 가능한 활성 고루틴이 0개가 되어 Go 런타임 런큐(Runqueue)가 멈춤")
			steps = append(steps, "Go 런타임이 'all goroutines are asleep - deadlock!' 치명적 에러를 발생시키며 즉시 종료")
		case "GoPanic":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				steps = append(steps, fmt.Sprintf("%s:%d 위치에서 런타임 패닉(Nil 포인터 또는 범위 초과) 발생", inc.CulpritCode.File, inc.CulpritCode.Line))
			} else {
				steps = append(steps, "애플리케이션 소스코드에서 미처리 런타임 패닉 발생")
			}
			steps = append(steps, "복구(recover) 함수 부재로 스택 언와인딩이 최상위 메인 함수까지 전파됨")
			steps = append(steps, fmt.Sprintf("Go 프로세스가 표준 에러에 스택트레이스를 출력하고 Exit code %s로 비정상 종료", exitCodeStr))
		case "DotNetNullReference":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				steps = append(steps, fmt.Sprintf("%s:%d (%s)에서 Null 객체 멤버 접근 시도", inc.CulpritCode.File, inc.CulpritCode.Line, inc.CulpritCode.Function))
			} else {
				steps = append(steps, ".NET 애플리케이션에서 NullReferenceException 예외 발생")
			}
			steps = append(steps, "전역 예외 처리 미들웨어에서 처리되지 않아 CLR 프로세스 중단")
		case "JVMHeapOOM":
			steps = append(steps, "JVM 힙 메모리(-Xmx) 한도에 도달하여 가비지 컬렉션(GC) 빈도 급증")
			steps = append(steps, "Full GC 이후에도 신규 객체 할당을 위한 메모리 공간 확보 실패")
			steps = append(steps, "java.lang.OutOfMemoryError: Java heap space 발생하며 JVM 프로세스 종료")
		default:
			steps = append(steps, fmt.Sprintf("컨테이너 상태 이상 감지 (RootCause: %s, ExitCode: %s)", inc.RootCause, exitCodeStr))
			if len(inc.MatchedEvents) > 0 {
				steps = append(steps, fmt.Sprintf("쿠버네티스 이벤트 매칭: %s", inc.MatchedEvents[0]))
			}
			steps = append(steps, "컨테이너 프로세스 종료 후 쿠버네티스 컨트롤러에 의해 재기동됨")
		}
	} else {
		// English default
		switch inc.RootCause {
		case "OOMKilled", "ProbableOOMKilled":
			steps = append(steps, "Container application memory consumption increased steadily")
			steps = append(steps, "Reached cgroup memory limit; memory allocation failed")
			steps = append(steps, fmt.Sprintf("Linux kernel OOM Killer terminated the process with SIGKILL (Exit code %s)", exitCodeStr))
			steps = append(steps, "Kubelet observed termination and restarted the container per restartPolicy")
		case "LivenessProbeFailure":
			steps = append(steps, "Application responsiveness degraded due to high load, deadlock, or pool exhaustion")
			steps = append(steps, "Health check endpoint failed to reply within configured timeoutSeconds")
			steps = append(steps, "Kubelet accumulated consecutive probe failures exceeding failureThreshold")
			steps = append(steps, fmt.Sprintf("Kubelet restarted the unresponsive container (Exit code %s)", exitCodeStr))
		case "GoDeadlock":
			steps = append(steps, "Mutual channel/lock contention occurred across all active goroutines")
			steps = append(steps, "No runnable goroutines remained on the Go runtime runqueue")
			steps = append(steps, "Go runtime fatal error triggered: 'all goroutines are asleep - deadlock!'")
		case "GoPanic":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				steps = append(steps, fmt.Sprintf("Runtime panic encountered at %s:%d", inc.CulpritCode.File, inc.CulpritCode.Line))
			} else {
				steps = append(steps, "Unhandled runtime panic occurred in application code")
			}
			steps = append(steps, "Stack unwinding propagated to top-level without recover()")
			steps = append(steps, fmt.Sprintf("Process dumped stack trace to stderr and terminated with exit code %s", exitCodeStr))
		case "DotNetNullReference":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				steps = append(steps, fmt.Sprintf("Null object dereference at %s:%d (%s)", inc.CulpritCode.File, inc.CulpritCode.Line, inc.CulpritCode.Function))
			} else {
				steps = append(steps, "NullReferenceException thrown in .NET runtime")
			}
			steps = append(steps, "Exception was unhandled, causing CLR process abort")
		case "JVMHeapOOM":
			steps = append(steps, "JVM heap limit (-Xmx) reached; GC thrashing observed")
			steps = append(steps, "Full GC failed to reclaim sufficient memory for new allocations")
			steps = append(steps, "java.lang.OutOfMemoryError: Java heap space thrown; JVM exited")
		default:
			steps = append(steps, fmt.Sprintf("Container termination detected (RootCause: %s, ExitCode: %s)", inc.RootCause, exitCodeStr))
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
			return "컨테이너가 설정된 메모리 상한선에 도달하여 리눅스 커널에 의해 강제 사살되었습니다. 메모리 누수 또는 트래픽 급증에 따른 버퍼 미회수가 의심됩니다."
		case "LivenessProbeFailure":
			return "애플리케이션이 외부 의존성(DB, 외부 API) 지연 또는 내부 락 경쟁으로 인해 헬스체크 응답을 제때 반환하지 못해 강제 재기동되었습니다."
		case "GoPanic", "GoDeadlock":
			return fmt.Sprintf("Go 애플리케이션 런타임 오류가 감지되었습니다%s. 처리되지 않은 패닉 또는 고루틴 동기화 실패가 원인입니다.", culpritStr)
		case "DotNetNullReference", "DotNetUnhandledException":
			return fmt.Sprintf(".NET 애플리케이션에서 처리되지 않은 런타임 예외가 발생했습니다%s.", culpritStr)
		case "PythonUnhandledException":
			return fmt.Sprintf("파이썬 스크립트 실행 도중 예외가 발생하여 비정상 종료되었습니다%s.", culpritStr)
		case "JVMHeapOOM":
			return "Java 힙 메모리가 소진되었습니다. 배치 작업 또는 캐시 데이터 누적으로 인해 가비지 컬렉터가 메모리를 회수하지 못했습니다."
		default:
			return fmt.Sprintf("컨테이너가 %s 원인으로 비정상 종료되었습니다%s.", inc.RootCause, culpritStr)
		}
	}

	// English default
	switch inc.RootCause {
	case "OOMKilled", "ProbableOOMKilled":
		return "Container hit the memory limit and was killed by the kernel OOM killer. Suspected causes include memory leaks or unconstrained batch buffering."
	case "LivenessProbeFailure":
		return "The application became unresponsive to liveness probes, likely due to heavy thread blocking, connection exhaustion, or internal deadlocks."
	case "GoPanic", "GoDeadlock":
		return fmt.Sprintf("Go runtime crash detected%s. Unhandled panic or synchronization deadlock caused immediate process exit.", culpritStr)
	case "DotNetNullReference", "DotNetUnhandledException":
		return fmt.Sprintf("Unhandled .NET exception terminated the CLR process%s.", culpritStr)
	case "PythonUnhandledException":
		return fmt.Sprintf("Unhandled Python exception caused process crash%s.", culpritStr)
	case "JVMHeapOOM":
		return "JVM exhausted allocated heap memory (-Xmx). Large object retention or collection memory leak prevented garbage collection."
	default:
		return fmt.Sprintf("Container terminated due to %s%s.", inc.RootCause, culpritStr)
	}
}

func buildSuggestedFix(inc IncidentContext, lang string) string {
	if lang == "ko" {
		switch inc.RootCause {
		case "OOMKilled", "ProbableOOMKilled":
			return "1) pod.spec.containers.resources.limits.memory를 현재 값의 1.5~2배로 증설하세요. 2) 대용량 파일/데이터 처리 시 전체를 메모리에 올리지 않고 스트리밍 방식으로 읽도록 리팩토링하세요."
		case "LivenessProbeFailure":
			return "1) livenessProbe의 timeoutSeconds를 5초 이상으로 늘리고 failureThreshold를 조정하세요. 2) 헬스체크(/healthz) 엔드포인트가 무거운 외부 DB 쿼리를 직접 수행하지 않도록 분리하세요."
		case "GoPanic":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				return fmt.Sprintf("해당 소스코드(%s:%d)에서 객체 참조 전 Nil 체크를 추가하거나 recover() 지연 함수를 통해 안전하게 에러를 핸들링하세요.", inc.CulpritCode.File, inc.CulpritCode.Line)
			}
			return "최상위 고루틴에 defer recover() 블록을 구현하여 패닉 발생 시 프로세스 전체가 즉시 크래시되지 않도록 방어 로직을 적용하세요."
		case "DotNetNullReference":
			if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
				return fmt.Sprintf("%s:%d의 참조 대상 객체가 null인지 확인하고, C#의 '?.' 연산자나 null 병합 연산자(??)를 적용하세요.", inc.CulpritCode.File, inc.CulpritCode.Line)
			}
			return "객체 인스턴스화 여부를 점검하고 전역 예외 처리(UseExceptionHandler) 미들웨어를 보강하세요."
		case "JVMHeapOOM":
			return "1) -Xmx 설정을 컨테이너 메모리 제한의 70~75% 수준으로 맞추세요. 2) -XX:+HeapDumpOnOutOfMemoryError 옵션을 활성화하여 힙 덤프를 추출하고 메모리 누수 클래스를 분석하세요."
		default:
			return "컨테이너 로그 및 종료 코드를 기반으로 애플리케이션 설정을 점검하고 파드 재시작 정책을 검토하세요."
		}
	}

	// English default
	switch inc.RootCause {
	case "OOMKilled", "ProbableOOMKilled":
		return "1) Increase pod memory limit (resources.limits.memory). 2) Switch bulk in-memory operations to streaming or chunked processing."
	case "LivenessProbeFailure":
		return "1) Increase probe timeoutSeconds and failureThreshold. 2) Ensure health check endpoint (/healthz) does not block on external downstream calls."
	case "GoPanic":
		if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
			return fmt.Sprintf("Inspect %s:%d for nil pointer or slice index out-of-range, and guard with nil check or defer recover().", inc.CulpritCode.File, inc.CulpritCode.Line)
		}
		return "Implement top-level defer recover() to prevent unexpected panics from crashing the entire process."
	case "DotNetNullReference":
		if inc.CulpritCode != nil && inc.CulpritCode.File != "" {
			return fmt.Sprintf("Verify object initialization at %s:%d, or use C# null-conditional operator (?. / ??).", inc.CulpritCode.File, inc.CulpritCode.Line)
		}
		return "Ensure dependent services and options are registered in DI container and add UseExceptionHandler middleware."
	case "JVMHeapOOM":
		return "1) Adjust -Xmx heap limit to 70-75% of pod memory limit. 2) Enable -XX:+HeapDumpOnOutOfMemoryError to capture and analyze heap dumps."
	default:
		return "Inspect recent application logs and verify pod resource requests and configurations."
	}
}
