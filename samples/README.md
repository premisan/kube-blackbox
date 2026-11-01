# Kube-Blackbox Failure Simulation Samples

이 디렉토리는 `kube-blackbox`의 다차원 진단 엔진과 원인 사슬(Root Cause Chain) 합성을 검증하기 위한 **38종의 카테고리별 실전 재시작 샘플 파드**를 제공합니다.

모든 샘플 파드는 쿠버네티스 표준 공식 경량 이미지(`busybox`, `alpine`, `python:3.11-alpine`, `node:18-alpine`, `amazoncorretto:17-alpine`)를 사용하며, 실제 운영 환경에서 발생하는 장애 시나리오를 재현합니다.

---

## 디렉토리 구조 및 카테고리별 샘플 목록

### 1. `samples/infrastructure/` (인프라, 스토리지, DNS 및 K8s 라이프사이클)
쿠버네티스 제어 평면, cgroup, CoreDNS, NFS 드라이버, Kubelet 프로브 및 노드 레벨 장애를 다룹니다.

| 파일명 | 파드명 | 진단 원인 (Root Cause) | 주요 시나리오 |
| :--- | :--- | :--- | :--- |
| `01-oomkilled.yaml` | `sample-oomkilled` | `OOMKilled` | cgroup 메모리 한도(30Mi)를 초과하여 리눅스 OOM Killer에 의해 137로 강제 종료 |
| `02-liveness-probe-failure.yaml` | `sample-liveness-failure` | `LivenessProbeFailure` | 컨테이너 헬스체크 파일 삭제 후 Kubelet Liveness Probe 실패로 인한 재시작 |
| `03-cpu-throttling-liveness.yaml` | `sample-cpu-throttling-liveness` | `LivenessProbeFailure` (CFS Throttling 연계) | 극도로 낮은 CPU 제한(50m) 하에서 고부하로 인한 프로브 타임아웃 복합 원인 |
| `04-init-container-failure.yaml` | `sample-init-container-failure` | `InitContainerFailed` | DB 마이그레이션 InitContainer 실패로 인한 메인 앱 기동 차단 및 재시작 |
| `05-startup-probe-timeout.yaml` | `sample-startup-probe-timeout` | `StartupProbeFailure` | 콜드 스타트 초기화 지연으로 Startup Probe 임계 시간 초과 종료 |
| `06-grace-period-timeout.yaml` | `sample-grace-period-timeout` | `GracePeriodExceeded` | SIGTERM 핸들러 블로킹으로 10초 grace period 초과 후 SIGKILL(137) 강제 종료 |
| `07-coredns-loop.yaml` | `sample-coredns-loop` | `CoreDNSLoopDetected` | 노드 resolv.conf 127.0.0.1 루프백 포워딩 무한 루프 감지 후 CoreDNS 긴급 정지 |
| `08-nfs-access-denied.yaml` | `sample-nfs-access-denied` | `NFSMountAccessDenied` | NFS 서버 익스포트 디렉토리 마운트 권한 거부(`mount.nfs: access denied`) |

### 2. `samples/application/` (애플리케이션 및 런타임 크래시)
다양한 언어 런타임(Go, Python, Java, Node.js, Rust, C/C++)의 메모리/예외/패닉 오류를 다룹니다.

| 파일명 | 파드명 | 진단 원인 (Root Cause) | 주요 시나리오 |
| :--- | :--- | :--- | :--- |
| `01-go-panic-nil-pointer.yaml` | `sample-go-panic` | `GoNilPointerDereference` | Go 런타임 nil pointer dereference 패닉 및 소스코드 위치 추출 |
| `02-python-unhandled-exception.yaml` | `sample-python-crash` | `PythonUnhandledException` | Python 3 `ValueError` 미처리 예외, 함수명 및 파일/라인 위치 정밀 추적 |
| `03-java-heap-oom.yaml` | `sample-java-crash` | `JVMHeapOOM` | JVM 힙 메모리(-Xmx32m) 고갈로 인한 `OutOfMemoryError: Java heap space` |
| `04-nodejs-unhandled-rejection.yaml` | `sample-nodejs-crash` | `NodeTypeError` | Node.js `TypeError: Cannot read properties of undefined` 오류 |
| `05-rust-panic-unwrap.yaml` | `sample-rust-panic` | `RustUnwrapNone` | Rust `Option::unwrap()` on `None` 패닉 및 파일/라인 추적 |
| `06-c-segfault.yaml` | `sample-c-segfault` | `SegmentationFault` | C/C++ 네이티브 메모리 침범으로 인한 세그멘테이션 오류 (SIGSEGV, Exit 139) |

### 3. `samples/configuration/` (설정, 웹서버 문법, 정책 및 보안 컨텍스트 오류)
컨테이너 이미지 아키텍처, 엔트리포인트, 파일 권한, Nginx 문법 오류, Kyverno 정책 차단, SecurityContext 제약 조건을 다룹니다.

| 파일명 | 파드명 | 진단 원인 (Root Cause) | 주요 시나리오 |
| :--- | :--- | :--- | :--- |
| `01-exec-format-mismatch.yaml` | `sample-exec-format-error` | `ArchitectureMismatch` | 노드 아키텍처 불일치로 인한 `cannot execute binary file: Exec format error` |
| `02-entrypoint-not-found.yaml` | `sample-entrypoint-not-found` | `CommandNotFound` | 엔트리포인트 실행 파일 부재로 인한 Exit Code 127 즉시 종료 |
| `03-permission-denied.yaml` | `sample-permission-denied` | `PermissionDenied` | 실행 권한 없는 스크립트 실행 시도로 인한 Permission Denied (Exit 126) |
| `04-readonly-root-filesystem.yaml` | `sample-readonly-rootfs` | `ReadOnlyRootFilesystem` | `readOnlyRootFilesystem: true` 제약 환경에서 루트 쓰기 시도 실패 |
| `05-run-as-non-root-violation.yaml` | `sample-nonroot-violation` | `PermissionDenied` | `runAsNonRoot: true` 비루트 환경에서 보호된 루트 파일 접근 차단 |
| `06-nginx-ingress-syntax-error.yaml` | `sample-nginx-syntax-error` | `NginxConfigSyntaxError` | Ingress-Nginx 설정 문법 오류(`nginx: [emerg]`)로 인한 기동 실패 |
| `07-kyverno-policy-violation.yaml` | `sample-kyverno-violation` | `KyvernoAdmissionPolicyViolation` | Kyverno ClusterPolicy 검증 규칙 위반으로 인한 어드미션 웹훅 생성 거절 |

### 4. `samples/dependency/` (외부 의존성, 네트워크, TLS, Egress 프록시, 서비스 메시 및 클라우드 SDK 장애)
데이터베이스, 메시지 브로커, TCP RST, TLS 인증서 체인, Squid Egress 프록시, Istio 메시, Envoy 서킷 브레이커, Vault 봉인, Gemini API 할당량, ClickHouse 파트 초과, LiteLLM 속도 제한 장애를 다룹니다.

| 파일명 | 파드명 | 진단 원인 (Root Cause) | 주요 시나리오 |
| :--- | :--- | :--- | :--- |
| `01-database-auth-failure.yaml` | `sample-db-auth-failure` | `DatabaseAuthFailure` | PostgreSQL 계정 인증 실패 (`password authentication failed for user`) |
| `02-database-connection-refused.yaml` | `sample-db-connection-refused` | `ConnectionRefused` | 대상 데이터베이스 포트 다운으로 인한 TCP 연결 거부 (`connection refused`) |
| `03-kafka-broker-unavailable.yaml` | `sample-kafka-broker-unavailable` | `KafkaBrokerUnavailable` | Kafka 클러스터 메타데이터 업데이트 타임아웃 및 브로커 리더 부재 |
| `04-port-conflict.yaml` | `sample-port-conflict` | `PortConflict` | 동일 포트(8080) 중복 바인딩 시도로 인한 `address already in use` |
| `05-sidecar-cascade-failure.yaml` | `sample-sidecar-cascade` | `SidecarCascadeFailure` | `auth-proxy` 사이드카 크래시로 인해 메인 앱이 연쇄 통신 실패 및 재시작 |
| `06-redis-oom-error.yaml` | `sample-redis-oom` | `RedisOOM` | Redis 메모리 초과(`OOM command not allowed when used memory > 'maxmemory'`) |
| `07-istio-race-condition.yaml` | `sample-istio-startup-race` | `IstioStartupRaceCondition` | `istio-proxy` 준비 전 메인 컨테이너 조기 기동 및 외부 연결 거부 크래시 |
| `08-envoy-circuit-breaker.yaml` | `sample-envoy-circuit-breaker` | `EnvoyCircuitBreakerOverflow` | Envoy Access Log `503 UO` 플래그 서킷 브레이커 오버플로우 감지 |
| `09-vault-agent-sealed.yaml` | `sample-vault-agent-sealed` | `VaultSealedFailure` | HashiCorp Vault 봉인(Sealed, HTTP 503)으로 인한 Vault Agent 시크릿 주입 실패 |
| `10-gcp-gemini-quota.yaml` | `sample-gemini-quota` | `GCPGeminiQuotaExceeded` | Google Gemini API 429 ResourceExhausted (분당 요청/토큰 쿼터 초과) |
| `11-clickhouse-too-many-parts.yaml` | `sample-clickhouse-parts` | `ClickHouseTooManyParts` | ClickHouse 고빈도 소형 INSERT로 인한 300+ 파트 머지 백프레셔 쓰기 차단 |
| `12-litellm-rate-limit.yaml` | `sample-litellm-ratelimit` | `LiteLLMRateLimitExceeded` | LiteLLM 프록시 연결 업스트림 LLM 프로바이더 429 속도 제한(TPM/RPM) 초과 |
| `13-network-connection-reset.yaml` | `sample-network-conn-reset` | `TCPConnectionReset` | 소켓 통신 중 원격 피어/방화벽에 의한 RST 패킷 수신 및 연결 강제 종료(`ECONNRESET`) |
| `14-tls-untrusted-ca.yaml` | `sample-tls-untrusted-ca` | `TLSUntrustedCA` | 사설/자체서명 CA 인증서 미신뢰(`PKIX path building failed`, `x509: certificate signed by unknown authority`) |
| `15-squid-proxy-auth-required.yaml` | `sample-squid-proxy-auth-required` | `SquidProxyAuthRequired` | Egress 프록시 인증 누락/실패(`407 Proxy Authentication Required`, `ERR_CACHE_ACCESS_DENIED`) |
| `16-squid-proxy-acl-denied.yaml` | `sample-squid-proxy-acl-denied` | `SquidProxyACLDenied` | Egress Squid 프록시 ACL 정책에 의한 외부 도메인/포트 차단(`403 Forbidden`, `ERR_ACCESS_DENIED`) |

---

## 실행 방법

### 특정 카테고리만 적용
```bash
# 애플리케이션 런타임 크래시 샘플 적용
kubectl apply -f samples/application/

# 인프라 장애 샘플 적용
kubectl apply -f samples/infrastructure/

# 설정 오류 샘플 적용
kubectl apply -f samples/configuration/

# 외부 의존성 샘플 적용
kubectl apply -f samples/dependency/
```

### 전체 샘플 일괄 적용 및 삭제
```bash
# 전체 샘플 일괄 적용 (하위 디렉토리 재귀 적용)
kubectl apply -R -f samples/

# 전체 샘플 일괄 정리
kubectl delete -R -f samples/ --ignore-not-found
```

### 진단 결과 확인
```bash
# 생성된 모든 PodRestartHistory 리소스 확인
kubectl get prh

# 특정 샘플의 정밀 인과 사슬 및 해결 가이드 확인
kubectl describe prh -l observer.io/pod-name=sample-python-crash
kubectl describe prh -l observer.io/pod-name=sample-sidecar-cascade
kubectl describe prh -l observer.io/pod-name=sample-cpu-throttling-liveness
```
