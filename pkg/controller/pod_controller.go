package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	observerv1alpha1 "github.com/premisan/kube-pinger/api/v1alpha1"
	"github.com/premisan/kube-pinger/pkg/analyzer"
)

// PodReconciler reconciles Pod restarts and generates PodRestartHistory CRs
type PodReconciler struct {
	client.Client
	KubeClient kubernetes.Interface
	Scheme     *runtime.Scheme
	Engine     *analyzer.DiagnosticEngine
}

func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("pod", req.NamespacedName)

	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Check container statuses (app containers + init containers)
	allStatuses := append([]corev1.ContainerStatus{}, pod.Status.ContainerStatuses...)
	allStatuses = append(allStatuses, pod.Status.InitContainerStatuses...)

	for _, cs := range allStatuses {
		if cs.RestartCount == 0 {
			continue
		}

		// Inspect all recorded restarts or the latest restart
		// By checking CR existence, we guarantee idempotency
		crName := GenerateCRName(pod.Name, cs.Name, cs.RestartCount)

		var existingCR observerv1alpha1.PodRestartHistory
		err := r.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: crName}, &existingCR)
		if err == nil {
			// Already diagnosed and recorded
			continue
		}
		if !apierrors.IsNotFound(err) {
			logger.Error(err, "Failed to check existing PodRestartHistory", "crName", crName)
			continue
		}

		// New restart detected! Fetch previous log and events, then diagnose.
		logger.Info("New restart detected, analyzing root cause",
			"container", cs.Name,
			"restartCount", cs.RestartCount,
		)

		prevLogs := r.fetchPreviousLogs(ctx, pod.Namespace, pod.Name, cs.Name)
		events := r.fetchPodEvents(ctx, pod.Namespace, pod.Name)

		diagInput := analyzer.DiagnosticInput{
			Pod:             &pod,
			ContainerName:   cs.Name,
			ContainerStatus: &cs,
			Events:          events,
			PreviousLogs:    prevLogs,
		}

		diagnosis, evidence := r.Engine.Diagnose(diagInput)

		restartedAt := metav1.Now()
		if cs.LastTerminationState.Terminated != nil && !cs.LastTerminationState.Terminated.FinishedAt.IsZero() {
			restartedAt = cs.LastTerminationState.Terminated.FinishedAt
		}

		newCR := &observerv1alpha1.PodRestartHistory{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crName,
				Namespace: pod.Namespace,
				Labels: map[string]string{
					"observer.io/pod-name":       sanitizeLabelValue(pod.Name),
					"observer.io/container-name": sanitizeLabelValue(cs.Name),
				},
				Annotations: map[string]string{
					"observer.io/pod-uid": string(pod.UID),
				},
			},
			Spec: observerv1alpha1.PodRestartHistorySpec{
				PodName:       pod.Name,
				ContainerName: cs.Name,
				RestartCount:  cs.RestartCount,
				RestartedAt:   restartedAt,
				Image:         cs.Image,
			},
		}

		if err := r.Create(ctx, newCR); err != nil {
			if apierrors.IsAlreadyExists(err) {
				continue
			}
			logger.Error(err, "Failed to create PodRestartHistory", "crName", crName)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, err
		}

		// Update Status
		newCR.Status = observerv1alpha1.PodRestartHistoryStatus{
			Diagnosis: diagnosis,
			Evidence:  evidence,
		}

		if err := r.Status().Update(ctx, newCR); err != nil {
			logger.Error(err, "Failed to update PodRestartHistory status", "crName", crName)
			return ctrl.Result{RequeueAfter: 3 * time.Second}, err
		}

		logger.Info("Successfully created PodRestartHistory",
			"crName", crName,
			"rootCause", diagnosis.RootCause,
			"confidence", diagnosis.Confidence,
		)
	}

	return ctrl.Result{}, nil
}

func (r *PodReconciler) fetchPreviousLogs(ctx context.Context, namespace, podName, containerName string) string {
	if r.KubeClient == nil {
		return ""
	}
	tailLines := int64(100)
	req := r.KubeClient.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
		Container: containerName,
		Previous:  true,
		TailLines: &tailLines,
	})

	stream, err := req.Stream(ctx)
	if err != nil {
		// Previous log might not exist yet or was garbage-collected
		return ""
	}
	defer stream.Close()

	buf := new(bytes.Buffer)
	_, _ = io.Copy(buf, stream)
	return buf.String()
}

func (r *PodReconciler) fetchPodEvents(ctx context.Context, namespace, podName string) []corev1.Event {
	if r.KubeClient == nil {
		return nil
	}
	list, err := r.KubeClient.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "involvedObject.name=" + podName,
	})
	if err != nil {
		return nil
	}
	return list.Items
}

// GenerateCRName produces a deterministic, DNS-1123 compliant resource name
func GenerateCRName(podName, containerName string, restartCount int32) string {
	raw := fmt.Sprintf("%s-%s-restart-%d", podName, containerName, restartCount)
	raw = strings.ToLower(raw)
	if len(raw) <= 250 {
		return raw
	}
	// Hash if too long
	hash := sha256.Sum256([]byte(raw))
	shortHash := hex.EncodeToString(hash[:])[:8]
	prefix := raw
	if len(prefix) > 230 {
		prefix = prefix[:230]
	}
	return fmt.Sprintf("%s-%s", prefix, shortHash)
}

func sanitizeLabelValue(val string) string {
	if len(val) > 63 {
		return val[:63]
	}
	return val
}

// PodRestartPredicate only enqueues Pods when restartCount has increased or restartCount > 0
func PodRestartPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			pod, ok := e.Object.(*corev1.Pod)
			if !ok {
				return false
			}
			return hasRestarts(pod)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldPod, okOld := e.ObjectOld.(*corev1.Pod)
			newPod, okNew := e.ObjectNew.(*corev1.Pod)
			if !okOld || !okNew {
				return false
			}
			return totalRestarts(newPod) > totalRestarts(oldPod)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return false
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
	}
}

func hasRestarts(pod *corev1.Pod) bool {
	return totalRestarts(pod) > 0
}

func totalRestarts(pod *corev1.Pod) int32 {
	var count int32
	for _, cs := range pod.Status.ContainerStatuses {
		count += cs.RestartCount
	}
	for _, cs := range pod.Status.InitContainerStatuses {
		count += cs.RestartCount
	}
	return count
}

func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		WithEventFilter(PodRestartPredicate()).
		Complete(r)
}
