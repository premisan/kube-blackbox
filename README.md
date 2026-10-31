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
```bash
kubectl get pods -n kube-pinger-system
```
*Example Output:*
```text
NAME                                             READY   STATUS    RESTARTS   AGE
kube-pinger-controller-manager-5f7bbd747d-abc12   1/1     Running   0          20s
```

Check real-time controller logs:
```bash
kubectl logs -f deployment/kube-pinger-controller-manager -n kube-pinger-system
```

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

Deploy 3 sample pods to test different restart failure scenarios:

### 1) Deploy Sample Pods
```bash
# 1) OOMKilled Pod (Allocates 50MB against 30Mi limit)
kubectl apply -f samples/01-oomkilled.yaml

# 2) Liveness Probe Failure Pod (Removes /tmp/healthy after 8 seconds)
kubectl apply -f samples/02-liveness-probe-failure.yaml

# 3) App Panic Pod (Go runtime panic stack trace on stderr)
kubectl apply -f samples/03-app-panic.yaml
```

### 2) Monitor Restart Diagnoses (`kubectl get prh`)
`additionalPrinterColumns` formats the output so root causes and exit codes are visible immediately:
```bash
# View across all namespaces (including kube-system)
kubectl get prh -A -w

# Or view default namespace
kubectl get prh -w
```

*Example Output:*
```text
NAMESPACE   NAME                                         POD                      CONTAINER         COUNT   ROOTCAUSE              CONFIDENCE   EXITCODE   AGE
default     sample-oomkilled-memory-eater-restart-1       sample-oomkilled         memory-eater      1       OOMKilled              High         137        15s
default     sample-liveness-failure-web-probe-restart-1  sample-liveness-failure  web-probe         1       LivenessProbeFailure   High         137        10s
default     sample-app-panic-backend-service-restart-1   sample-app-panic         backend-service   1       AppPanic               High         2          5s
```

### 3) Inspect Diagnostic Evidence (`kubectl describe prh <name>`)
```bash
kubectl describe prh sample-liveness-failure-web-probe-restart-1
```
*Example Output:*
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

## 6. Cleanup

```bash
# Remove sample pods
make delete-samples

# Remove controller deployment and RBAC
kubectl delete -f config/deploy/deploy.yaml

# Remove CRD (optional)
kubectl delete -f config/crd/bases/observer.io_podrestarthistories.yaml
```

---

## 7. License

Distributed under the MIT License. See `LICENSE` for more information.
