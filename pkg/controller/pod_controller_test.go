package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	observerv1alpha1 "github.com/premisan/kube-pinger/api/v1alpha1"
	"github.com/premisan/kube-pinger/pkg/analyzer"
)

func TestGenerateCRName(t *testing.T) {
	name := GenerateCRName("my-pod", "app", 1)
	expected := "my-pod-app-restart-1"
	if name != expected {
		t.Fatalf("expected %s, got %s", expected, name)
	}

	// Test long name
	longPod := strings.Repeat("a", 300)
	longName := GenerateCRName(longPod, "container", 5)
	if len(longName) > 253 {
		t.Fatalf("expected length <= 253, got %d", len(longName))
	}
}

func TestPodRestartPredicate(t *testing.T) {
	p := PodRestartPredicate()

	podNoRestart := &corev1.Pod{
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", RestartCount: 0},
			},
		},
	}
	podWithRestart := &corev1.Pod{
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", RestartCount: 1},
			},
		},
	}

	// CreateFunc
	if p.Create(event.CreateEvent{Object: podNoRestart}) {
		t.Fatalf("expected CreateFunc to return false for 0 restarts")
	}
	if !p.Create(event.CreateEvent{Object: podWithRestart}) {
		t.Fatalf("expected CreateFunc to return true for >0 restarts")
	}

	// UpdateFunc
	if !p.Update(event.UpdateEvent{ObjectOld: podNoRestart, ObjectNew: podWithRestart}) {
		t.Fatalf("expected UpdateFunc to return true when restarts increased")
	}
	if p.Update(event.UpdateEvent{ObjectOld: podWithRestart, ObjectNew: podWithRestart}) {
		t.Fatalf("expected UpdateFunc to return false when restarts did not increase")
	}
}

func TestPodReconciler_ReconcileOOM(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = observerv1alpha1.AddToScheme(scheme)

	exitCode := int32(137)
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-oom-pod",
			Namespace: "default",
			UID:       "12345-uid",
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:         "worker",
					RestartCount: 1,
					Image:        "alpine:latest",
					LastTerminationState: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode:   exitCode,
							Reason:     "OOMKilled",
							FinishedAt: metav1.Now(),
						},
					},
				},
			},
		},
	}

	cb := clientfake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&observerv1alpha1.PodRestartHistory{}).
		WithObjects(testPod)
	fakeClient := cb.Build()
	fakeKubeClient := fake.NewSimpleClientset()

	reconciler := &PodReconciler{
		Client:     fakeClient,
		KubeClient: fakeKubeClient,
		Scheme:     scheme,
		Engine:     analyzer.NewDiagnosticEngine(),
	}

	req := ctrl.Request{
		NamespacedName: client.ObjectKey{
			Namespace: "default",
			Name:      "test-oom-pod",
		},
	}

	res, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}
	if res.Requeue || res.RequeueAfter > 0 {
		t.Fatalf("expected no requeue, got %v", res)
	}

	// Verify CR was created
	crName := GenerateCRName("test-oom-pod", "worker", 1)
	var cr observerv1alpha1.PodRestartHistory
	if err := fakeClient.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: crName}, &cr); err != nil {
		t.Fatalf("failed to fetch created CR: %v", err)
	}

	if cr.Spec.PodName != "test-oom-pod" || cr.Spec.ContainerName != "worker" || cr.Spec.RestartCount != 1 {
		t.Fatalf("spec mismatch: %+v", cr.Spec)
	}
	if cr.Status.Diagnosis.RootCause != "OOMKilled" {
		t.Fatalf("expected diagnosis RootCause OOMKilled, got %s", cr.Status.Diagnosis.RootCause)
	}
	if cr.Status.Diagnosis.Confidence != "High" {
		t.Fatalf("expected diagnosis Confidence High, got %s", cr.Status.Diagnosis.Confidence)
	}
}

func TestPodReconciler_PruneExcessHistories(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = observerv1alpha1.AddToScheme(scheme)

	cr1 := &observerv1alpha1.PodRestartHistory{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-pod-app-restart-1",
			Namespace: "default",
			Labels: map[string]string{
				"observer.io/pod-name":       "my-pod",
				"observer.io/container-name": "app",
			},
		},
		Spec: observerv1alpha1.PodRestartHistorySpec{
			PodName:       "my-pod",
			ContainerName: "app",
			RestartCount:  1,
		},
	}
	cr2 := &observerv1alpha1.PodRestartHistory{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-pod-app-restart-2",
			Namespace: "default",
			Labels: map[string]string{
				"observer.io/pod-name":       "my-pod",
				"observer.io/container-name": "app",
			},
		},
		Spec: observerv1alpha1.PodRestartHistorySpec{
			PodName:       "my-pod",
			ContainerName: "app",
			RestartCount:  2,
		},
	}
	cr3 := &observerv1alpha1.PodRestartHistory{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-pod-app-restart-3",
			Namespace: "default",
			Labels: map[string]string{
				"observer.io/pod-name":       "my-pod",
				"observer.io/container-name": "app",
			},
		},
		Spec: observerv1alpha1.PodRestartHistorySpec{
			PodName:       "my-pod",
			ContainerName: "app",
			RestartCount:  3,
		},
	}

	cb := clientfake.NewClientBuilder().WithScheme(scheme).WithObjects(cr1, cr2, cr3)
	fakeClient := cb.Build()

	reconciler := &PodReconciler{
		Client:                 fakeClient,
		Scheme:                 scheme,
		MaxHistoryPerContainer: 2, // Only keep 2!
	}

	reconciler.pruneExcessHistories(context.Background(), "default", "my-pod", "app")

	var list observerv1alpha1.PodRestartHistoryList
	_ = fakeClient.List(context.Background(), &list)
	if len(list.Items) != 2 {
		t.Fatalf("expected exactly 2 items remaining, got %d", len(list.Items))
	}

	// Verify cr1 (restart 1) was deleted, and cr2, cr3 remain
	for _, item := range list.Items {
		if item.Spec.RestartCount == 1 {
			t.Fatalf("expected restart 1 to be pruned, but still found")
		}
	}
}

func TestPodReconciler_CleanExpiredHistories(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = observerv1alpha1.AddToScheme(scheme)

	expiredTime := metav1.Time{Time: time.Now().Add(-8 * 24 * time.Hour)} // 8 days ago
	freshTime := metav1.Time{Time: time.Now().Add(-1 * 24 * time.Hour)}   // 1 day ago

	expiredCR := &observerv1alpha1.PodRestartHistory{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "expired-prh",
			Namespace:         "default",
			CreationTimestamp: expiredTime,
		},
	}
	freshCR := &observerv1alpha1.PodRestartHistory{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "fresh-prh",
			Namespace:         "default",
			CreationTimestamp: freshTime,
		},
	}

	cb := clientfake.NewClientBuilder().WithScheme(scheme).WithObjects(expiredCR, freshCR)
	fakeClient := cb.Build()

	reconciler := &PodReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		HistoryTTL: 7 * 24 * time.Hour, // 7 days
	}

	reconciler.cleanExpiredHistories(context.Background(), 7*24*time.Hour)

	var list observerv1alpha1.PodRestartHistoryList
	_ = fakeClient.List(context.Background(), &list)
	if len(list.Items) != 1 {
		t.Fatalf("expected 1 item remaining, got %d", len(list.Items))
	}
	if list.Items[0].Name != "fresh-prh" {
		t.Fatalf("expected fresh-prh remaining, got %s", list.Items[0].Name)
	}
}
