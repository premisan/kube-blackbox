# Kube-Pinger (Pod Restart Observer)

[![Docker Hub](https://img.shields.io/docker/pulls/premisan0/kube-pinger?logo=docker&label=Docker%20Hub)](https://hub.docker.com/r/premisan0/kube-pinger)
[![Go Report Card](https://goreportcard.com/badge/github.com/premisan/kube-pinger)](https://goreportcard.com/report/github.com/premisan/kube-pinger)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> [한국어 (Korean Version)](README.ko.md)

**Kube-Pinger** is a lightweight Kubernetes controller that monitors pod restarts in real time, automatically deduces root causes via rule-based heuristics across **LastTerminationState**, **Kubelet Events**, and **Previous Container Logs**, and records the diagnosis directly into a custom resource (`PodRestartHistory`).

Stop digging through past logs and multiple `kubectl` commands. Simply run `kubectl get prh` to see why your pods restarted.

---

## 1. Diagnostic Pipeline & Architecture

```text
[Pod Restart Detected (restartCount increased)]
       │
       ▼
1. LastTerminationState Inspection
   ├── reason == OOMKilled ─────────────────► [OOMKilled (Confidence: High)]
   └── exitCode in (126, 127) ──────────────► [PermissionDenied / CommandNotFound]
       │
       ▼
2. Recent K8s Events Cross-Check (Probe, Node Eviction, Preemption)
   ├── Liveness / Startup Probe Failed ─────► [LivenessProbeFailure / StartupProbeFailure]
   ├── Evicted / Node low on resource ──────► [NodeEviction]
   └── Preempted by higher priority pod ────► [Preempted]
       │
       ▼
3. Previous Container Logs Regex Pattern Matching (Tail 100 lines)
   ├── Go panic / JVM OutOfMemoryError ─────► [AppPanic / JVMOOM]
   ├── Address already in use ──────────────► [PortConflict]
   ├── Fatal error / SIGSEGV ───────────────► [AppFatalError / SegmentationFault]
   └── Unhandled Exception (Python, Node) ──► [AppUnhandledException]
       │
       ▼
4. Fallback Heuristic (ExitCode Mapping)
   └── 137(Sigkill), 143(Sigterm), 139(Sigsegv), 1(RuntimeError), 0(ExitedNormally)
       │
       ▼
[Create / Update PodRestartHistory CRD]
```

---

## 2. Project Structure

```text
kube-pinger/
├── api/
│   └── v1alpha1/
│       ├── groupversion_info.go
│       └── podrestarthistory_types.go          # Go CRD struct definition
├── config/
│   ├── crd/
│   │   └── bases/
│   │       └── observer.io_podrestarthistories.yaml # CRD YAML manifest
│   ├── deploy/
│   │   └── deploy.yaml                         # All-in-one deployment (Namespace, RBAC, Deployment)
│   └── rbac/
│       └── rbac.yaml                           # RBAC manifests
├── pkg/
│   ├── analyzer/                               # Rule-based diagnostic engine
│   │   ├── analyzer.go
│   │   ├── analyzer_test.go
│   │   ├── events.go                           # Event correlation & filtering
│   │   └── log_patterns.go                     # Previous log regex rules
│   └── controller/
│       ├── pod_controller.go                   # Pod Watcher & Reconciler
│       └── pod_controller_test.go
├── samples/                                    # Sample crash pods for testing
│   ├── 01-oomkilled.yaml                       # Triggers cgroup OOMKilled
│   ├── 02-liveness-probe-failure.yaml          # Triggers Liveness Probe failure
│   └── 03-app-panic.yaml                       # Triggers Go runtime panic
├── .dockerignore
├── Dockerfile
├── Makefile
├── go.mod
├── go.sum
└── main.go                                     # Controller entrypoint
```

---

## 3. Kubernetes Deployment Guide

The official container image `premisan0/kube-pinger:latest` supports multi-architecture (`linux/amd64` and `linux/arm64`). You can deploy it to any Kubernetes cluster (AWS EKS, GKE, Docker Desktop, kind, k3s, minikube) without building locally.

### Step 1: Install CRD
```bash
kubectl apply -f https://raw.githubusercontent.com/premisan/kube-pinger/main/config/crd/bases/observer.io_podrestarthistories.yaml
# Or with local clone:
# kubectl apply -f config/crd/bases/observer.io_podrestarthistories.yaml
```

### Step 2: Deploy Controller
Deploys `kube-pinger-system` namespace, RBAC permissions, and the controller deployment:
```bash
kubectl apply -f https://raw.githubusercontent.com/premisan/kube-pinger/main/config/deploy/deploy.yaml
# Or with local clone:
# kubectl apply -f config/deploy/deploy.yaml
```

### Step 3: Verify Controller Status
By default, Kube-Pinger deploys in a 2-replica High Availability (HA) configuration using Kubernetes Leader Election (`coordination.k8s.io/leases`):
```bash
kubectl get pods -n kube-pinger-system
```
*Example Output:*
```text
NAME                                             READY   STATUS    RESTARTS   AGE
kube-pinger-controller-manager-5f7bbd747d-abc12   1/1     Running   0          20s
kube-pinger-controller-manager-5f7bbd747d-xyz34   1/1     Running   0          20s
```

Check real-time controller logs (Active Leader will show `Successfully acquired lease` and `Starting workers`):
```bash
kubectl logs -f deployment/kube-pinger-controller-manager -n kube-pinger-system
```

### Controller Retention & HA Configuration Flags

Kube-Pinger includes built-in HA and safeguards to protect etcd from flooding:
- **`--leader-elect`** (Default: `true`): Enables Active-Standby leader election via Kubernetes Leases for safe multi-replica deployments.
- **`--max-history-per-container`** (Default: `5`): Keeps only the latest 5 restart records per container. When a container enters `CrashLoopBackOff`, older records are automatically pruned.
- **`--history-ttl`** (Default: `168h` / 7 days): Background GC worker periodically cleans up records older than 7 days. Pod restart records remain accessible even if the pod or spot node is deleted during cluster scaling or maintenance.

---

## 4. Local Development (Optional)

You can also run Kube-Pinger as a local Go process targeting your current kubeconfig context:

```bash
# 1) Register CRD
kubectl apply -f config/crd/bases/observer.io_podrestarthistories.yaml

# 2) Run controller locally
go run main.go
```

To build container images locally:
```bash
# Local image build
docker build -t premisan0/kube-pinger:latest .

# Multi-arch image build via buildx
docker buildx build --platform linux/amd64,linux/arm64 -t premisan0/kube-pinger:latest --push .
```

---

## 5. Testing & Verification

Deploy the test sample pods all at once to verify multi-language and infrastructure failure diagnoses:

### 1) Deploy All Sample Pods at Once
```bash
# Deploys all 5 failure test pods (OOM, Probe Failure, Go Panic, Python Exception, Java Heap OOM)
kubectl apply -f samples/
# Or using Makefile:
# make deploy-samples
```

### 2) Monitor Restart Diagnoses (`kubectl get prh`)
`additionalPrinterColumns` formats the output so category, root causes, confidence, and exit codes are visible immediately:
```bash
# View across all namespaces (including kube-system)
kubectl get prh -A -w

# Or view default namespace
kubectl get prh -w
```

*Example Output:*
```text
NAMESPACE   NAME                                         POD                      CONTAINER         COUNT   CATEGORY         ROOTCAUSE                  CONFIDENCE   EXITCODE   AGE
default     sample-oomkilled-memory-eater-restart-1       sample-oomkilled         memory-eater      1       Infrastructure   OOMKilled                  High         137        15s
default     sample-liveness-failure-web-probe-restart-1  sample-liveness-failure  web-probe         1       Infrastructure   LivenessProbeFailure       High         137        10s
default     sample-app-panic-backend-service-restart-1   sample-app-panic         backend-service   1       Application      GoPanic                    High         2          8s
default     sample-python-crash-python-worker-restart-1  sample-python-crash      python-worker     1       Application      PythonUnhandledException   High         1          5s
default     sample-java-crash-java-backend-restart-1     sample-java-crash        java-backend      1       Application      JVMHeapOOM                 High         1          3s
```

### 3) Inspect Diagnostic Evidence & Mitigation Guide (`kubectl describe prh <name>`)
```bash
kubectl describe prh sample-java-crash-java-backend-restart-1
```
*Example Output:*
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
```

---

## 6. Cleanup

```bash
# Remove all sample pods
kubectl delete -f samples/ --ignore-not-found
# Or via Makefile:
# make delete-samples

# Remove controller deployment and RBAC
kubectl delete -f config/deploy/deploy.yaml

# Remove CRD (optional)
kubectl delete -f config/crd/bases/observer.io_podrestarthistories.yaml
```

---

## 7. License

Distributed under the MIT License. See `LICENSE` for more information.
