# Kube-Pinger (Pod Restart Observer)

[![Docker Hub](https://img.shields.io/docker/pulls/premisan0/kube-pinger?logo=docker&label=Docker%20Hub)](https://hub.docker.com/r/premisan0/kube-pinger)
[![Go Report Card](https://goreportcard.com/badge/github.com/premisan/kube-pinger)](https://goreportcard.com/report/github.com/premisan/kube-pinger)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> [English Version](README.md)

쿠버네티스 파드의 재시작(`restartCount` 증가)을 실시간으로 감지하고 종료 상태(`LastTerminationState`), 쿠버네티스 이벤트(`Events`), 직전 컨테이너 로그(`Previous Logs`)를 교차 분석하여 근본 원인을 진단한 뒤 `PodRestartHistory` CRD로 자동 기록하는 쿠버네티스 컨트롤러입니다.

파드가 재시작되었을 때 여러 `kubectl` 명령어와 과거 로그를 일일이 뒤질 필요 없이, `kubectl get prh` 명령어로 재시작 원인을 한 번에 파악할 수 있습니다.

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
│   ├── deploy/
│   │   └── deploy.yaml                         # 원클릭 배포 매니페스트 (Namespace, RBAC, Deployment)
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
├── .dockerignore
├── Dockerfile
├── Makefile
├── go.mod
├── go.sum
└── main.go                                     # 컨트롤러 진입점
```

---

## 3. 쿠버네티스 클러스터 배포 가이드

`premisan0/kube-pinger:latest` 이미지는 `linux/amd64` 및 `linux/arm64` 멀티 아키텍처를 공식 지원하므로, 어떤 클러스터 환경(Intel x86, Apple Silicon, AWS Graviton 등)에서든 추가 빌드 없이 즉시 배포할 수 있습니다.

### 1단계: CRD 등록
```bash
kubectl apply -f https://raw.githubusercontent.com/premisan/kube-pinger/main/config/crd/bases/observer.io_podrestarthistories.yaml
# 또는 로컬 파일인 경우:
# kubectl apply -f config/crd/bases/observer.io_podrestarthistories.yaml
```

### 2단계: 컨트롤러 배포
`kube-pinger-system` 네임스페이스, RBAC 권한, Deployment 컨트롤러가 한 번에 배포됩니다.
```bash
kubectl apply -f https://raw.githubusercontent.com/premisan/kube-pinger/main/config/deploy/deploy.yaml
# 또는 로컬 파일인 경우:
# kubectl apply -f config/deploy/deploy.yaml
```

### 3단계: 배포 상태 확인
```bash
kubectl get pods -n kube-pinger-system
```
*출력 예시:*
```text
NAME                                             READY   STATUS    RESTARTS   AGE
kube-pinger-controller-manager-5f7bbd747d-abc12   1/1     Running   0          25s
```

컨트롤러 실시간 로그 확인:
```bash
kubectl logs -f deployment/kube-pinger-controller-manager -n kube-pinger-system
```

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
docker build -t premisan0/kube-pinger:latest .

# 멀티 아키텍처 빌드 (buildx)
docker buildx build --platform linux/amd64,linux/arm64 -t premisan0/kube-pinger:latest --push .
```

---

## 5. 재시작 진단 테스트 및 확인

### 1) 샘플 파드 3종 배포
```bash
# 1) OOMKilled 파드 배포 (메모리 리밋 30Mi 초과)
kubectl apply -f samples/01-oomkilled.yaml

# 2) Liveness Probe 실패 파드 배포 (8초 후 헬스체크 파일 삭제)
kubectl apply -f samples/02-liveness-probe-failure.yaml

# 3) App Panic 크래시 파드 배포 (Go 패닉 스택 트레이스 출력 후 크래시)
kubectl apply -f samples/03-app-panic.yaml
```

### 2) 진단 결과 실시간 확인 (`kubectl get prh`)
`additionalPrinterColumns`가 설정되어 있어 주요 진단 결과가 한눈에 표시됩니다.
```bash
# 전체 네임스페이스 조회 (kube-system 포함)
kubectl get prh -A -w

# 또는 default 네임스페이스만 조회
kubectl get prh -w
```

*출력 예시:*
```text
NAMESPACE   NAME                                         POD                      CONTAINER         COUNT   ROOTCAUSE              CONFIDENCE   EXITCODE   AGE
default     sample-oomkilled-memory-eater-restart-1       sample-oomkilled         memory-eater      1       OOMKilled              High         137        15s
default     sample-liveness-failure-web-probe-restart-1  sample-liveness-failure  web-probe         1       LivenessProbeFailure   High         137        10s
default     sample-app-panic-backend-service-restart-1   sample-app-panic         backend-service   1       AppPanic               High         2          5s
```

### 3) 상세 증거 및 로그 스니펫 확인 (`kubectl describe prh <name>`)
```bash
kubectl describe prh sample-liveness-failure-web-probe-restart-1
```
*출력 예시:*
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

## 6. 리소스 정리

```bash
# 샘플 파드 삭제
make delete-samples

# kube-pinger 컨트롤러 및 RBAC 언디플로이
kubectl delete -f config/deploy/deploy.yaml

# CRD 삭제 (선택)
kubectl delete -f config/crd/bases/observer.io_podrestarthistories.yaml
```
