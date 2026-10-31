package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
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

// PodReconciler reconciles Pod restarts, creates diagnoses, and manages retention & TTL.
type PodReconciler struct {
	client.Client
	KubeClient             kubernetes.Interface
	Scheme                 *runtime.Scheme
	Engine                 *analyzer.DiagnosticEngine
	MaxHistoryPerContainer int
	HistoryTTL             time.Duration
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
			Status: observerv1alpha1.PodRestartHistoryStatus{
				Diagnosis: diagnosis,
				Evidence:  evidence,
			},
		}

		if err := r.Create(ctx, newCR); err != nil {
			if apierrors.IsAlreadyExists(err) {
				continue
			}
			logger.Error(err, "Failed to create PodRestartHistory", "crName", crName)
			return ctrl.Result{}, err
		}

		// Update Status via status subresource, fallback to standard update if needed
		newCR.Status = observerv1alpha1.PodRestartHistoryStatus{
			Diagnosis: diagnosis,
			Evidence:  evidence,
		}

		if err := r.Status().Update(ctx, newCR); err != nil {
			if errUpdate := r.Update(ctx, newCR); errUpdate != nil {
				logger.Error(err, "Failed to update PodRestartHistory status", "crName", crName)
				return ctrl.Result{}, err
			}
		}

		logger.Info("Successfully created PodRestartHistory",
			"crName", crName,
			"category", diagnosis.Category,
			"rootCause", diagnosis.RootCause,
			"confidence", diagnosis.Confidence,
		)

		// Prune older histories exceeding MaxHistoryPerContainer
		r.pruneExcessHistories(ctx, pod.Namespace, pod.Name, cs.Name)
	}

	return ctrl.Result{}, nil
}

// pruneExcessHistories deletes older PodRestartHistory records exceeding MaxHistoryPerContainer
func (r *PodReconciler) pruneExcessHistories(ctx context.Context, namespace, podName, containerName string) {
	maxHistory := r.MaxHistoryPerContainer
	if maxHistory <= 0 {
		maxHistory = 5
	}

	logger := log.FromContext(ctx).WithValues("pod", podName, "container", containerName)

	var list observerv1alpha1.PodRestartHistoryList
	err := r.List(ctx, &list,
		client.InNamespace(namespace),
		client.MatchingLabels{
			"observer.io/pod-name":       sanitizeLabelValue(podName),
			"observer.io/container-name": sanitizeLabelValue(containerName),
		},
	)
	if err != nil {
		logger.Error(err, "Failed to list PodRestartHistories for pruning")
		return
	}

	if len(list.Items) <= maxHistory {
		return
	}

	// Sort items by RestartCount ascending (oldest first)
	sort.Slice(list.Items, func(i, j int) bool {
		return list.Items[i].Spec.RestartCount < list.Items[j].Spec.RestartCount
	})

	excessCount := len(list.Items) - maxHistory
	for i := 0; i < excessCount; i++ {
		item := list.Items[i]
		if err := r.Delete(ctx, &item); err != nil && !apierrors.IsNotFound(err) {
			logger.Error(err, "Failed to delete excess PodRestartHistory", "crName", item.Name)
		} else {
			logger.Info("Pruned older PodRestartHistory exceeding max history limit",
				"crName", item.Name,
				"restartCount", item.Spec.RestartCount,
				"maxAllowed", maxHistory,
			)
		}
	}
}

// Start implements manager.Runnable to execute the periodic TTL cleaner
func (r *PodReconciler) Start(ctx context.Context) error {
	return r.RunTTLCleaner(ctx)
}

// RunTTLCleaner periodically checks for and deletes PodRestartHistory records exceeding HistoryTTL
func (r *PodReconciler) RunTTLCleaner(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("ttl-cleaner")

	ttl := r.HistoryTTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour // default 7 days
	}

	logger.Info("Starting periodic TTL garbage collection worker", "ttl", ttl)

	// Run once immediately, then periodically every hour
	r.cleanExpiredHistories(ctx, ttl)

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Stopping TTL garbage collection worker")
			return nil
		case <-ticker.C:
			r.cleanExpiredHistories(ctx, ttl)
		}
	}
}

func (r *PodReconciler) cleanExpiredHistories(ctx context.Context, ttl time.Duration) {
	logger := log.FromContext(ctx).WithName("ttl-cleaner")

	var list observerv1alpha1.PodRestartHistoryList
	if err := r.List(ctx, &list); err != nil {
		logger.Error(err, "Failed to list PodRestartHistories for TTL cleanup")
		return
	}

	now := time.Now()
	deletedCount := 0

	for _, item := range list.Items {
		age := now.Sub(item.CreationTimestamp.Time)
		if age > ttl {
			if err := r.Delete(ctx, &item); err != nil && !apierrors.IsNotFound(err) {
				logger.Error(err, "Failed to delete expired PodRestartHistory", "crName", item.Name)
			} else {
				deletedCount++
				logger.Info("Deleted expired PodRestartHistory",
					"crName", item.Name,
					"age", age.Round(time.Minute).String(),
					"ttl", ttl.String(),
				)
			}
		}
	}

	if deletedCount > 0 {
		logger.Info("TTL cleanup finished", "deletedCount", deletedCount)
	}
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
	if r.MaxHistoryPerContainer <= 0 {
		r.MaxHistoryPerContainer = 5
	}
	if r.HistoryTTL <= 0 {
		r.HistoryTTL = 7 * 24 * time.Hour // default 7 days
	}

	// Register TTL Cleaner as background runner
	if err := mgr.Add(r); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		WithEventFilter(PodRestartPredicate()).
		Complete(r)
}
