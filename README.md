# Kube-Pinger (Pod Restart Observer)

쿠버네티스 파드의 재시작(`restartCount` 증가)을 실시간으로 감지하고, **종료 상태(LastTerminationState)**, **쿠버네티스 이벤트(Events)**, **직전 컨테이너 로그(Previous Logs)**를 교차 분석하여 근본 원인을 진단한 뒤 `PodRestartHistory` CRD로 자동 기록하는 쿠버네티스 컨트롤러입니다.

이제 파드가 재시작되었을 때 여러 `kubectl` 명령어와 과거 로그를 일일이 뒤질 필요 없이, `kubectl get prh` 명령어로 재시작 원인을 한 번에 파악할 수 있습니다.

---

## 1. 아키텍처 및 진단 파이프라인

```text
[파드 재시작 감지 (restartCount 증가)]
       │
       ▼
1. LastTerminationState 분석
   ├── reason == OOMKilled ─────────────────► [OOMKilled (Confidence: High)]
   └── exitCode in (126, 127) ──────────────► [PermissionDenied / CommandNotFound]
       │
       ▼
2. 최근 K8s Events 교차 대조 (Probe, Node Eviction, Preemption)
   ├── Liveness / Startup Probe Failed ─────► [LivenessProbeFailure / StartupProbeFailure]
   ├── Evicted / Node low on resource ──────► [NodeEviction]
   └── Preempted by other pod ──────────────► [Preempted]
       │
       ▼
3. Previous Container Logs 정규식 패턴 분석 (Tail 100 lines)
   ├── Go panic / JVM OutOfMemoryError ─────► [AppPanic / JVMOOM]
   ├── Address already in use ──────────────► [PortConflict]
   ├── Fatal error / SIGSEGV ───────────────► [AppFatalError / SegmentationFault]
   └── Unhandled Exception (Python, Node) ──► [AppUnhandledException]
       │
       ▼
4. Fallback (ExitCode 기반 휴리스틱 매핑)
   └── 137(Sigkill), 143(Sigterm), 139(Sigsegv), 1(RuntimeError), 0(ExitedNormally)
       │
       ▼
[PodRestartHistory CRD 생성 및 상태 기록]
```

---

## 2. 프로젝트 구조

```text
kube-pinger/
├── api/
│   └── v1alpha1/
│       ├── groupversion_info.go
│       └── podrestarthistory_types.go          # Go CRD 정의
├── config/
│   ├── crd/
│   │   └── bases/
│   │       └── observer.io_podrestarthistories.yaml # CRD YAML
│   └── rbac/
│       └── rbac.yaml                           # RBAC 매니페스트
├── pkg/
│   ├── analyzer/                               # 규칙 기반 진단 엔진
│   │   ├── analyzer.go
│   │   ├── analyzer_test.go
│   │   ├── events.go                           # 이벤트 교차 검증
│   │   └── log_patterns.go                     # 이전 로그 정규식 패턴
│   └── controller/
│       ├── pod_controller.go                   # Pod Watcher & Reconciler
│       └── pod_controller_test.go
├── samples/                                    # 테스트용 재시작 샘플 파드 3종
│   ├── 01-oomkilled.yaml                       # OOMKilled 유발
│   ├── 02-liveness-probe-failure.yaml          # Liveness Probe 실패 유발
│   └── 03-app-panic.yaml                       # Go 런타임 패닉 크래시 유발
├── Dockerfile
├── Makefile
├── go.mod
├── go.sum
└── main.go                                     # 컨트롤러 진입점
```

---

## 3. 로컬 클러스터에서 테스트하기

### 1단계: CRD 등록
```bash
kubectl apply -f config/crd/bases/observer.io_podrestarthistories.yaml
```

### 2단계: 컨트롤러 실행
로컬 개발 환경에서 직접 실행:
```bash
go run main.go
```
또는 클러스터 내 Pod로 배포 시 `config/rbac/rbac.yaml` 적용 후 배포합니다.

### 3단계: 샘플 테스트 파드 배포
새 터미널을 열고 재시작을 유발하는 파드 3종을 배포합니다.
```bash
# 1) OOMKilled 파드 배포 (메모리 리밋 30Mi 초과 유발)
kubectl apply -f samples/01-oomkilled.yaml

# 2) Liveness Probe 실패 파드 배포 (8초 후 헬스체크 파일 삭제)
kubectl apply -f samples/02-liveness-probe-failure.yaml

# 3) App Panic 크래시 파드 배포 (Go 패닉 스택 트레이스 출력 후 크래시)
kubectl apply -f samples/03-app-panic.yaml
```

### 4단계: 진단 결과 확인

#### 목록 요약 보기 (`kubectl get prh`)
`additionalPrinterColumns`가 설정되어 있어 주요 진단 결과가 한눈에 표시됩니다.
클러스터 전체 네임스페이스(예: kube-system 등)의 재시작 히스토리를 보려면 `-A` 옵션을 사용합니다:
```bash
kubectl get prh -A -w
```
또는 현재 네임스페이스(default)만 조회:
```bash
kubectl get prh -w
```
출력 예시:
```text
NAME                                         POD                      CONTAINER         COUNT   ROOTCAUSE              CONFIDENCE   EXITCODE   AGE
sample-oomkilled-memory-eater-restart-1       sample-oomkilled         memory-eater      1       OOMKilled              High         137        15s
sample-liveness-failure-web-probe-restart-1  sample-liveness-failure  web-probe         1       LivenessProbeFailure   High         137        10s
sample-app-panic-backend-service-restart-1   sample-app-panic         backend-service   1       AppPanic               High         2          5s
```

#### 상세 증거 확인 (`kubectl describe prh <name>`)
```bash
kubectl describe prh sample-liveness-failure-web-probe-restart-1
```
출력 예시:
```yaml
Spec:
  Container Name:  web-probe
  Pod Name:        sample-liveness-failure
  Restart Count:   1
  Restarted At:    2026-10-31T10:45:12Z
Status:
  Diagnosis:
    Confidence:    High
    Root Cause:    LivenessProbeFailure
    Summary:       Container failed liveness probe: Liveness probe failed: cat: can't open '/tmp/healthy': No such file or directory
  Evidence:
    Exit Code:           137
    Matched Events:
      [Warning] Unhealthy: Liveness probe failed: cat: can't open '/tmp/healthy': No such file or directory (count: 2)
      [Normal] Killing: Container web-probe failed liveness probe, will be restarted (count: 1)
```

---

## 4. 테스트 정리
```bash
make delete-samples
```
