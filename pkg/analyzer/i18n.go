package analyzer

import (
	"fmt"
	"strings"
)

type LocalizedText struct {
	SummaryTpl        string
	RecommendedAction string
}

// i18nRegistry stores localized messages keyed by [lang][rootCause]
var i18nRegistry = map[string]map[string]LocalizedText{
	"ko": {
		"OOMKilled": {
			SummaryTpl:        "컨테이너 메모리 제한(Limit)을 초과하여 Linux 커널 OOM Killer(cgroup 메모리 고갈)에 의해 강제 종료되었습니다.",
			RecommendedAction: "파드 스펙의 메모리 제한(resources.limits.memory)을 증설하거나 애플리케이션의 메모리 누수를 프로파일링하세요.",
		},
		"ProbableOOMKilled": {
			SummaryTpl:        "메모리 제한이 설정된 상태에서 메모리 고갈 관련 에러와 함께 프로세스가 강제 사살(SIGKILL/137)되었습니다.",
			RecommendedAction: "파드 메모리 제한을 증설하거나 힙 덤프를 통해 메모리 소비를 최적화하세요.",
		},
		"PermissionDenied": {
			SummaryTpl:        "컨테이너 진입점 바이너리/스크립트의 실행 권한이 없습니다 (Exit code 126).",
			RecommendedAction: "Dockerfile 또는 진입점 스크립트에 실행 권한(chmod +x)을 부여하세요.",
		},
		"CommandNotFound": {
			SummaryTpl:        "컨테이너 진입점 실행 파일이나 셸 명령어를 이미지 PATH에서 찾을 수 없습니다 (Exit code 127).",
			RecommendedAction: "Dockerfile의 ENTRYPOINT/CMD 경로를 확인하고 베이스 이미지에 필요한 셸 및 바이너리가 존재하는지 확인하세요.",
		},
		"LivenessProbeFailure": {
			SummaryTpl:        "Liveness Probe(활성도 검사)가 반복 실패하여 Kubelet이 컨테이너를 재시작했습니다.",
			RecommendedAction: "헬스체크 엔드포인트(/healthz)의 지연 시간을 점검하고 probe의 timeoutSeconds/failureThreshold를 조정하세요.",
		},
		"StartupProbeFailure": {
			SummaryTpl:        "애플리케이션 초기화 시간이 지정된 시간 내에 완료되지 않아 Startup Probe가 실패했습니다.",
			RecommendedAction: "startupProbe의 initialDelaySeconds 또는 failureThreshold를 늘려 초기화 시간을 충분히 확보하세요.",
		},
		"NodeEviction": {
			SummaryTpl:        "노드의 가용 리소스(메모리 또는 디스크) 부족으로 인해 파드가 노드에서 축출(Eviction)되었습니다.",
			RecommendedAction: "노드의 리소스 사용량을 점검하거나 파드를 여유 있는 다른 노드로 스케줄링하세요.",
		},
		"Preempted": {
			SummaryTpl:        "더 높은 우선순위(PriorityClass)를 가진 파드에게 리소스를 양보하기 위해 선점(Preemption)되었습니다.",
			RecommendedAction: "파드의 PriorityClass를 검토하거나 노드 풀 용량을 증설하세요.",
		},
		"SigkillTerminated": {
			SummaryTpl:        "프로세스가 강제 종료 신호(SIGKILL, 137)를 수신했습니다. 기록되지 않은 OOM, Probe 타임아웃 또는 강제 축출 가능성이 높습니다.",
			RecommendedAction: "노드 dmesg 로그에서 OOM Killer 발생 여부를 확인하거나 Liveness Probe 타임아웃을 점검하세요.",
		},
		"SigtermShutdown": {
			SummaryTpl:        "배포 롤아웃, 오토스케일링, 노드 드레인 등의 이유로 정상 종료 신호(SIGTERM, 143)를 수신하고 종료되었습니다.",
			RecommendedAction: "배포 작업 중 발생한 정상 재시작인지 확인하고, 예상치 못한 경우 Deployment 이력을 점검하세요.",
		},
		"SegmentationFault": {
			SummaryTpl:        "잘못된 메모리 주소 참조(Segmentation Fault, SIGSEGV, 139)로 인해 프로세스가 비정상 종료되었습니다.",
			RecommendedAction: "네이티브 C/C++ 라이브러리, Unsafe 포인터 또는 손상된 공유 메모리 객체를 점검하세요.",
		},
		"NativeAbort": {
			SummaryTpl:        "프로세스가 SIGABRT(134) 신호 또는 네이티브 assert 실패로 인해 강제 중단되었습니다.",
			RecommendedAction: "C/C++ 수준의 assert문 조건 또는 네이티브 라이브러리 초기화 실패 여부를 점검하세요.",
		},
		"JVMHeapOOM": {
			SummaryTpl:        "JVM 힙 메모리가 고갈되었습니다 (java.lang.OutOfMemoryError: Java heap space).",
			RecommendedAction: "JVM 힙 제한(-Xmx) 및 파드 메모리 제한을 증설하거나 힙 덤프를 분석하여 메모리 누수를 해결하세요.",
		},
		"JVMMetaspaceOOM": {
			SummaryTpl:        "JVM 메타스페이스(Metaspace) 메모리가 고갈되었습니다.",
			RecommendedAction: "-XX:MaxMetaspaceSize를 증설하거나 동적 프록시/클래스로더 누수를 점검하세요.",
		},
		"JVMDirectMemoryOOM": {
			SummaryTpl:        "JVM 다이렉트 버퍼(Direct Memory) 메모리가 고갈되었습니다.",
			RecommendedAction: "NIO / Netty의 ByteBuf 해제 누락 여부를 확인하거나 -XX:MaxDirectMemorySize를 조정하세요.",
		},
		"JVMStackOverflow": {
			SummaryTpl:        "과도한 재귀 호출로 인해 JVM 호출 스택이 오버플로우되었습니다 (StackOverflowError).",
			RecommendedAction: "호출 스택의 무한 재귀 함수 로직을 점검하거나 스레드 스택 크기(-Xss)를 검토하세요.",
		},
		"SpringBootStartupFailure": {
			SummaryTpl:        "스프링 부트 애플리케이션 컨텍스트 초기화 실패 (BeanCreationException 등).",
			RecommendedAction: "설정 파일(application.yml)의 프로퍼티 값 및 누락된 빈(Bean) 의존성을 확인하세요.",
		},
		"GoPanic": {
			SummaryTpl:        "Go 런타임 패닉(Panic) 크래시: %s",
			RecommendedAction: "콜스택을 분석하여 Nil 포인터 역참조 또는 슬라이스 범위 초과(Index out of range)를 예외 처리하세요.",
		},
		"GoDeadlock": {
			SummaryTpl:        "Go 런타임에서 모든 고루틴이 영구 대기 상태에 빠진 교착 상태(Deadlock)를 감지했습니다.",
			RecommendedAction: "뮤텍스 Lock/Unlock 순서와 채널 송수신 동기화 로직을 점검하세요.",
		},
		"GoConcurrentMapAccess": {
			SummaryTpl:        "동기화 락 없이 표준 맵에 동시 읽기/쓰기가 발생하여 Go 프로세스가 충돌했습니다.",
			RecommendedAction: "sync.RWMutex로 맵 접근을 보호하거나 sync.Map으로 대체하세요.",
		},
		"PythonUnhandledException": {
			SummaryTpl:        "처리되지 않은 파이썬 예외(Unhandled Exception)로 인해 프로세스가 종료되었습니다.",
			RecommendedAction: "오류 스니펫의 트레이스백을 확인하여 예외 처리(try-except)를 보강하세요.",
		},
		"PythonMemoryError": {
			SummaryTpl:        "파이썬 프로세스의 메모리 허용량을 초과했습니다 (MemoryError).",
			RecommendedAction: "대용량 데이터프레임/배치 로딩을 분할 처리하거나 파드 메모리 제한을 증설하세요.",
		},
		"PythonModuleNotFound": {
			SummaryTpl:        "파이썬 모듈 의존성을 찾을 수 없습니다: %s",
			RecommendedAction: "requirements.txt에 누락된 패키지를 추가하고 이미지를 다시 빌드하세요.",
		},
		"NodeHeapOOM": {
			SummaryTpl:        "Node.js V8 엔진의 자바스크립트 힙 메모리가 고갈되었습니다.",
			RecommendedAction: "NODE_OPTIONS=\"--max-old-space-size=4096\"으로 힙 크기를 늘리거나 메모리 누수를 프로파일링하세요.",
		},
		"NodeModuleNotFound": {
			SummaryTpl:        "Node.js 모듈 의존성을 찾을 수 없습니다: %s",
			RecommendedAction: "package.json 의존성을 확인하고 빌드 시 npm/yarn install이 정상 실행되었는지 확인하세요.",
		},
		"NodeUnhandledPromiseRejection": {
			SummaryTpl:        "처리되지 않은 프로미스 거부(Unhandled Promise Rejection) 또는 미처리 예외로 충돌했습니다.",
			RecommendedAction: "비동기 Promise 호출에 .catch() 핸들러를 추가하거나 try/catch 블록으로 감싸세요.",
		},
		"RustPanic": {
			SummaryTpl:        "러스트(Rust) 스레드 패닉 발생: %s",
			RecommendedAction: "참조된 소스코드 위치에서 unwrap()/expect() 호출을 점검하고 에러 처리를 보강하세요.",
		},
		"DotNetNullReference": {
			SummaryTpl:        ".NET 런타임 널 포인터 참조 오류 (System.NullReferenceException).",
			RecommendedAction: "참조 객체가 초기화되었는지 확인하거나 C# Nullable Reference Types(?.) 연산자를 사용하세요.",
		},
		"DotNetOOM": {
			SummaryTpl:        ".NET CLR 힙 메모리가 고갈되었습니다 (System.OutOfMemoryException).",
			RecommendedAction: "대용량 LOH(Large Object Heap) 할당을 점검하거나 파드 메모리 한도를 늘리세요.",
		},
		"DotNetUnhandledException": {
			SummaryTpl:        ".NET 애플리케이션의 처리되지 않은 예외로 프로세스가 중단되었습니다: %s",
			RecommendedAction: "예외 스택트레이스를 분석하여 전역 예외 처리 미들웨어를 보강하세요.",
		},
		"PHPMemoryExhausted": {
			SummaryTpl:        "PHP 스크립트 실행 허용 메모리를 초과했습니다 (Allowed memory size exhausted).",
			RecommendedAction: "php.ini의 memory_limit 설정을 늘리거나 루프 내 메모리 해제를 최적화하세요.",
		},
		"PHPUncaughtError": {
			SummaryTpl:        "PHP 스크립트에서 처리되지 않은 치명적 오류(Fatal error)가 발생했습니다: %s",
			RecommendedAction: "해당 PHP 파일의 구문 오류 및 try-catch 블록을 점검하세요.",
		},
		"RubyNoMemoryError": {
			SummaryTpl:        "Ruby 프로세스 메모리가 고갈되었습니다 (NoMemoryError).",
			RecommendedAction: "대용량 객체 할당 로직을 점검하고 파드 메모리 제한을 증설하세요.",
		},
		"RubySystemStackError": {
			SummaryTpl:        "Ruby 호출 스택 깊이 초과 (SystemStackError: stack level too deep).",
			RecommendedAction: "무한 루프 또는 과도한 재귀 호출이 발생하는 루틴을 수정하세요.",
		},
		"PortConflict": {
			SummaryTpl:        "포트 바인딩 충돌이 감지되었습니다 (Address already in use): %s",
			RecommendedAction: "컨테이너의 리슨 포트를 변경하거나 포트를 선점하고 있는 다른 프로세스가 없는지 확인하세요.",
		},
		"DatabaseAuthFailure": {
			SummaryTpl:        "데이터베이스 연결 계정 인증에 실패했습니다.",
			RecommendedAction: "DB 접속용 Secret(사용자명, 비밀번호) 및 접근 권한을 확인하세요.",
		},
		"TLSValidationFailed": {
			SummaryTpl:        "외부 의존성 서비스 연결 중 TLS/SSL 인증서 검증에 실패했습니다.",
			RecommendedAction: "사내 프라이빗 CA 인증서를 마운트하거나 인증서 만료일을 확인하세요.",
		},
		"ConnectionRefused": {
			SummaryTpl:        "연결 대상 서비스가 포트 접속을 거부했습니다 (Connection refused).",
			RecommendedAction: "업스트림 DB, 캐시, API 파드가 정상 기동 중인지 및 NetworkPolicy를 확인하세요.",
		},
		"DNSLookupFailed": {
			SummaryTpl:        "도메인 DNS 주소 조회에 실패했습니다: %s",
			RecommendedAction: "CoreDNS 동작 상태, kube-dns 서비스 및 도메인 철자를 확인하세요.",
		},
		"RedisOOM": {
			SummaryTpl:        "Redis 메모리가 maxmemory 설정 한도에 도달하여 쓰기 명령이 거부되었습니다.",
			RecommendedAction: "Redis maxmemory를 증설하거나 maxmemory-policy(allkeys-lru 등) 캐시 퇴출 정책을 설정하세요.",
		},
		"DiskNoSpaceLeft": {
			SummaryTpl:        "컨테이너 로컬 파일시스템에 남은 디스크 용량이 없습니다 (No space left on device).",
			RecommendedAction: "임시 파일(/tmp), 로그 파일 누적을 확인하고 ephemeral-storage 요청/한도를 늘리세요.",
		},
		"NginxWorkerConnections": {
			SummaryTpl:        "Nginx의 동시 접속량이 한도를 초과했습니다 (worker_connections are not enough).",
			RecommendedAction: "nginx.conf의 worker_connections 및 worker_processes 수치를 상향 조정하세요.",
		},
	},
	"ja": {
		"OOMKilled": {
			SummaryTpl:        "コンテナのメモリ制限を超過し、LinuxカーネルOOM Killerにより強制終了されました。",
			RecommendedAction: "Podのメモリリミット(resources.limits.memory)を増やすか、メモリリークを調査してください。",
		},
		"LivenessProbeFailure": {
			SummaryTpl:        "Liveness Probe(生存確認)が連続して失敗し、Kubeletにより再起動されました。",
			RecommendedAction: "ヘルスチェックエンドポイントの応答時間を確認し、Probeのタイムアウト値を調整してください。",
		},
		"GoPanic": {
			SummaryTpl:        "Goランタイムパニックによるクラッシュ: %s",
			RecommendedAction: "コールスタックを確認し、Nullポインタ参照やスライス境界外エラーを修正してください。",
		},
		"JVMHeapOOM": {
			SummaryTpl:        "JVMヒープメモリが枯渇しました (java.lang.OutOfMemoryError: Java heap space)。",
			RecommendedAction: "JVMの-XmxおよびPodのメモリ制限を増やすか、ヒープダンプを解析してください。",
		},
	},
}

// Localize resolves localized summary and recommendedAction based on rootCause and target language.
// Falls back to the provided default English strings if no localization entry is found.
func Localize(rootCause, lang string, defaultSummary, defaultAction string, detail string) (string, string) {
	lang = strings.ToLower(strings.TrimSpace(lang))
	if lang == "" || lang == "en" {
		summary := defaultSummary
		if strings.Contains(summary, "%s") && detail != "" {
			summary = fmt.Sprintf(summary, detail)
		}
		return summary, defaultAction
	}

	langMap, ok := i18nRegistry[lang]
	if !ok {
		// Unsupported language, fallback to English
		summary := defaultSummary
		if strings.Contains(summary, "%s") && detail != "" {
			summary = fmt.Sprintf(summary, detail)
		}
		return summary, defaultAction
	}

	entry, ok := langMap[rootCause]
	if !ok {
		summary := defaultSummary
		if strings.Contains(summary, "%s") && detail != "" {
			summary = fmt.Sprintf(summary, detail)
		}
		return summary, defaultAction
	}

	summary := entry.SummaryTpl
	if strings.Contains(summary, "%s") && detail != "" {
		summary = fmt.Sprintf(summary, detail)
	}
	return summary, entry.RecommendedAction
}
