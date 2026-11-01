# Kube-Blackbox (Pod Restart Observer & Flight Recorder)

[![Docker Hub](https://img.shields.io/docker/pulls/premisan0/kube-blackbox?logo=docker&label=Docker%20Hub&color=066da5)](https://hub.docker.com/r/premisan0/kube-blackbox)
[![Go Report Card](https://goreportcard.com/badge/github.com/premisan/kube-blackbox)](https://goreportcard.com/report/github.com/premisan/kube-blackbox)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> [English Version](README.md)

쿠버네티스 파드의 재시작(`restartCount` 증가)을 실시간으로 감지하고 종료 상태(`LastTerminationState`), 쿠버네티스 이벤트(`Events`), 직전 컨테이너 로그(`Previous Logs`)를 규칙 및 사실 기반 엔진으로 정밀 교차 분석하여 근본 원인과 인과관계 사슬을 `PodRestartHistory` CRD로 자동 기록하는 쿠버네티스 지능형 관측 컨트롤러입니다.

파드가 재시작되었을 때 여러 `kubectl` 명령어와 과거 로그를 일일이 뒤질 필요 없이, `kubectl get prh` 명령어로 재시작 원인을 한 번에 파악할 수 있습니다.

---

## 1. 아키텍처 및 진단 파이프라인

```text
[파드 재시작 감지 (restartCount 증가)]
       │
       ▼
1. LastTerminationState & POSIX 신호 분석
   ├── reason == OOMKilled ─────────────────► [OOMKilled (Confidence: High)]
   ├── exitCode in (126, 127) ──────────────► [PermissionDenied / CommandNotFound]
   └── exitCode == 137 & GracePeriod 초과 ──► [GracefulShutdownTimeout]
       │
       ▼
2. 최근 K8s Events 및 리소스 제약 교차 대조 (Probe, Node Eviction, CPU Throttling)
   ├── Liveness / Startup Probe Failed ─────► [LivenessProbeFailure / StartupProbeFailure]
   ├── Evicted / Node low on resource ──────► [NodeEviction]
   └── Preempted by other pod ──────────────► [Preempted]
       │
       ▼
3. Previous Container Logs & 시맨틱 역추적
   ├── Go panic / JVM OutOfMemoryError ─────► [AppPanic / JVMOOM]
   ├── C/C++ glibc / V8 heap crash ─────────► [HeapCorruption / NodeV8FatalError]
   ├── read-only file system ───────────────► [ReadOnlyRootFilesystem]
   ├── Address already in use / Redis OOM ──► [PortConflict / RedisOOM]
   ├── Nginx connections / Storage ENOSPC ──► [NginxWorkerConnections / DiskNoSpaceLeft]
   └── Unhandled Exception (Python, Node) ──► [AppUnhandledException]
       │
       ▼
4. 내장 시맨틱 합성기 (Embedded Synthesizer, 비동기 워커)
   └── 수집된 사실(Fact) 기반으로 원인 연쇄 사슬(RootCauseChain) 및 조치 가이드 생성 (ko/en)
       │
       ▼
[PodRestartHistory CRD 생성 및 상태 기록]
```

---

## 2. 프로젝트 구조

```text
kube-blackbox/
├── api/
│   └── v1alpha1/
│       ├── groupversion_info.go
│       └── podrestarthistory_types.go          # Go CRD 정의
├── config/
│   ├── crd/
│   │   └── bases/
│   │       └── observer.io_podrestarthistories.yaml # CRD YAML
│   ├── deploy/
│   │   └── deploy.yaml                         # 원클릭 배포 매니페스트 (Namespace, RBAC, Deployment)
│   └── rbac/
│       └── rbac.yaml                           # RBAC 매니페스트
├── pkg/
│   ├── analyzer/                               # 규칙 기반 진단 엔진
│   │   ├── analyzer.go
│   │   ├── analyzer_test.go
│   │   ├── events.go                           # 이벤트 교차 검증
│   │   ├── i18n.go                             # 다국어 번역 사전
│   │   ├── knowledge/                          # 임베디드 시그니처 및 POSIX 신호 사전
│   │   │   ├── exitcodes.go
│   │   │   ├── signals.go
│   │   │   └── signatures.go
│   │   ├── log_patterns.go                     # 로그 패턴 및 범인 코드(CulpritCode) 추출
│   │   ├── log_preprocess.go                   # 구조화 JSON 로그 언패커
│   │   └── sidecar.go                          # 사이드카 및 InitContainer 연쇄 분석
│   ├── controller/
│   │   ├── pod_controller.go                   # Pod Watcher & 비동기 합성 Reconciler
│   │   └── pod_controller_test.go
│   └── synthesizer/                            # 결정론적 인과관계 사슬 합성 엔진
│       ├── synthesizer.go
│       ├── synthesizer_test.go
│       └── types.go
├── samples/                                    # 테스트용 재시작 샘플 파드 5종
│   ├── 01-oomkilled.yaml                       # OOMKilled 유발
│   ├── 02-liveness-probe-failure.yaml          # Liveness Probe 실패 유발
│   ├── 03-app-panic.yaml                       # Go 런타임 패닉 크래시 유발
│   ├── 04-python-crash.yaml                    # Python 미처리 예외(Unhandled Exception) 유발
│   └── 05-java-crash.yaml                      # JVM 힙 메모리 고갈(OutOfMemoryError) 유발
├── .dockerignore
├── Dockerfile
├── Makefile
├── go.mod
├── go.sum
└── main.go                                     # 컨트롤러 진입점
```

---

## 3. 쿠버네티스 클러스터 배포 가이드

`premisan0/kube-blackbox:latest` 이미지는 `linux/amd64` 및 `linux/arm64` 멀티 아키텍처를 공식 지원하므로, 어떤 클러스터 환경(Intel x86, Apple Silicon, AWS Graviton 등)에서든 추가 빌드 없이 즉시 배포할 수 있습니다.

### 1단계: CRD 등록
```bash
kubectl apply -f https://raw.githubusercontent.com/premisan/kube-blackbox/main/config/crd/bases/observer.io_podrestarthistories.yaml
# 또는 로컬 파일인 경우:
# kubectl apply -f config/crd/bases/observer.io_podrestarthistories.yaml
```

### 2단계: 컨트롤러 배포
`kube-blackbox` 네임스페이스, RBAC 권한, Deployment 컨트롤러가 한 번에 배포됩니다:
```bash
kubectl apply -f https://raw.githubusercontent.com/premisan/kube-blackbox/main/config/deploy/deploy.yaml
# 또는 로컬 파일인 경우:
# kubectl apply -f config/deploy/deploy.yaml
```

### 3단계: 배포 상태 확인
기본적으로 쿠버네티스 리더 선출(Leader Election)을 통해 2개의 리플리카가 Active-Standby 고가용성(HA) 구조로 자동 배포됩니다:
```bash
kubectl get pods -n kube-blackbox
```
*출력 예시:*
```text
NAME                             READY   STATUS    RESTARTS   AGE
kube-blackbox-5f7bbd747d-abc12   1/1     Running   0          25s
kube-blackbox-5f7bbd747d-xyz34   1/1     Running   0          25s
```

컨트롤러 실시간 로그 확인 (리더 파드가 분산 락을 획득하고 작업을 수행합니다):
```bash
kubectl logs -f deployment/kube-blackbox -n kube-blackbox
```

### 컨트롤러 설정 플래그 (다국어 지원, HA, 보존 정책)

Kube-Blackbox는 다국어 인과관계 합성, 고가용성(HA) 및 etcd 부하를 방지하기 위한 안전장치를 기본 탑재하고 있습니다:
- `--leader-elect` (기본값: `true`): `coordination.k8s.io/leases` 분산 락을 이용한 Active-Standby 리더 선출을 활성화합니다.
- `--analysis-language` (기본값: `ko`): 진단서 및 인사이트의 기본 출력 언어 설정 (공식 지원: `ko` 한국어, `en` 영어). 미지원 언어 입력 시 투명하게 `ko`로 폴백 표기. 환경변수 `ANALYSIS_LANGUAGE` 또는 개별 파드의 `observer.io/language` 어노테이션으로 오버라이드 가능.
- `--log-tail-lines` (기본값: `500`): 분석용으로 수집할 직전 컨테이너 로그의 최대 라인 수.
- `--max-history-per-container` (기본값: `5`): 컨테이너당 최신 5개의 재시작 기록만 유지합니다. 파드가 `CrashLoopBackOff`로 수십 번 재시작되어도 오래된 기록은 자동으로 실시간 삭제되어 etcd 도배를 방지합니다.
- `--history-ttl` (기본값: `168h` / 7일): 생성된 지 7일이 지난 오래된 기록을 백그라운드 워커가 주기적으로 자동 청소합니다. 스팟 인스턴스 반환이나 롤링 배포로 파드가 이미 삭제되었더라도 7일 동안 원인 기록이 안전하게 보존됩니다.

---

## 4. 로컬 개발 환경 실행 (선택사항)

클러스터 파드로 배포하지 않고 로컬 머신에서 바이너리로 직접 구동하여 개발/테스트할 수도 있습니다:

```bash
# 1) CRD 등록
kubectl apply -f config/crd/bases/observer.io_podrestarthistories.yaml

# 2) 컨트롤러 로컬 실행 (현재 kubeconfig 컨텍스트 사용)
go run main.go
```

직접 Docker 이미지를 빌드하려는 경우:
```bash
# 로컬 빌드
docker build -t premisan0/kube-blackbox:latest .

# 멀티 아키텍처 빌드 (buildx)
docker buildx build --platform linux/amd64,linux/arm64 -t premisan0/kube-blackbox:latest --push .
```

---

## 5. 재시작 진단 테스트 및 확인

다양한 언어와 인프라 장애 시나리오를 검증하기 위해 테스트 샘플 파드들을 한 번에 배포할 수 있습니다:

### 1) 샘플 파드 전체 한 번에 배포
```bash
# 5가지 장애 시나리오 파드 전체 배포 (OOM, Probe 실패, Go Panic, Python 예외, Java Heap OOM)
kubectl apply -f samples/
# 또는 Makefile 이용:
# make deploy-samples
```

### 2) 진단 결과 실시간 확인 (`kubectl get prh`)
`additionalPrinterColumns`가 설정되어 있어 카테고리, 근본 원인, 신뢰도, 종료 코드가 한눈에 표시됩니다.
```bash
# 전체 네임스페이스 조회 (kube-system 포함)
kubectl get prh -A -w

# 또는 default 네임스페이스만 조회
kubectl get prh -w
```

*출력 예시:*
```text
NAMESPACE   NAME                                         POD                      CONTAINER         COUNT   CATEGORY         ROOTCAUSE                  CONFIDENCE   EXITCODE   AGE
default     sample-oomkilled-memory-eater-restart-1       sample-oomkilled         memory-eater      1       Infrastructure   OOMKilled                  High         137        15s
default     sample-liveness-failure-web-probe-restart-1  sample-liveness-failure  web-probe         1       Infrastructure   LivenessProbeFailure       High         137        10s
default     sample-app-panic-backend-service-restart-1   sample-app-panic         backend-service   1       Application      GoPanic                    High         2          8s
default     sample-python-crash-python-worker-restart-1  sample-python-crash      python-worker     1       Application      PythonUnhandledException   High         1          5s
default     sample-java-crash-java-backend-restart-1     sample-java-crash        java-backend      1       Application      JVMHeapOOM                 High         1          3s
```

### 3) 상세 증거 및 해결 조치 가이드 확인 (`kubectl describe prh <name>`)
```bash
kubectl describe prh sample-java-crash-java-backend-restart-1
```
*출력 예시:*
```yaml
Spec:
  Container Name:  java-backend
  Pod Name:        sample-java-crash
  Restart Count:   1
  Restarted At:    2026-10-31T11:28:15Z
Status:
  Diagnosis:
    Category:            Application
    Confidence:          High
    Root Cause:          JVMHeapOOM
    Summary:             JVM exhausted heap memory (java.lang.OutOfMemoryError: Java heap space)
    Recommended Action:  Increase JVM -Xmx heap limit, increase Pod memory limit, or profile memory leaks with heap dump.
  Evidence:
    Error Class:         OutOfMemoryError
    Exit Code:           1
    Last Log Snippet:    [INFO] Rapid heap allocation loop beginning...
                         Exception in thread "main" java.lang.OutOfMemoryError: Java heap space
                         at MemoryHog.main(MemoryHog.java:13)
  Insight:
    Analyzed:            true
    Confidence:          High
    Engine:              rule-synthesizer
    Inferred Context:    Java 힙 메모리가 소진되었습니다. 배치 작업 또는 캐시 데이터 누적으로 인해 가비지 컬렉터가 메모리를 회수하지 못했습니다.
    Language:            ko
    Suggested Fix:       JVM -Xmx 힙 설정을 확장하거나 메모리 누수를 프로파일링하십시오.
    Root Cause Chain:
      - Step: 1
        Cause: Process exited with non-zero status
        Description: Container terminated with exit code 1
      - Step: 2
        Cause: Log signature matched OutOfMemoryError
        Description: Last logs contain JVM heap exhaustion pattern
```

---

## 6. 리소스 정리

```bash
# 샘플 파드 전체 한 번에 삭제
kubectl delete -f samples/ --ignore-not-found
# 또는 Makefile 이용:
# make delete-samples

# kube-blackbox 컨트롤러 및 RBAC 언디플로이
kubectl delete -f config/deploy/deploy.yaml

# CRD 삭제 (선택)
kubectl delete -f config/crd/bases/observer.io_podrestarthistories.yaml
```

---

## 7. 라이선스

MIT 라이선스에 따라 배포됩니다. 자세한 내용은 `LICENSE`를 참고하세요.
