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
	// Without UID
	nameWithoutUID := GenerateCRName("my-pod", "", "app", 1)
	expectedWithoutUID := "my-pod-app-restart-1"
	if nameWithoutUID != expectedWithoutUID {
		t.Fatalf("expected %s, got %s", expectedWithoutUID, nameWithoutUID)
	}

	// With UID (e.g. StatefulSet pods)
	nameWithUID := GenerateCRName("web-0", "a1b2c3d4-e5f6-7890", "app", 1)
	expectedWithUID := "web-0-a1b2c-app-restart-1"
	if nameWithUID != expectedWithUID {
		t.Fatalf("expected %s, got %s", expectedWithUID, nameWithUID)
	}

	// Test long name
	longPod := strings.Repeat("a", 300)
	longName := GenerateCRName(longPod, "test-uid", "container", 5)
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
	crName := GenerateCRName("test-oom-pod", "12345-uid", "worker", 1)
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

func TestPodReconciler_StatefulSetRecreationCollisionAvoidance(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = observerv1alpha1.AddToScheme(scheme)

	// Older pod instance of web-0
	oldPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-0",
			Namespace: "default",
			UID:       "11111-old-uid",
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:         "nginx",
					RestartCount: 1,
					LastTerminationState: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode:   137,
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
		WithObjects(oldPod)
	fakeClient := cb.Build()
	fakeKubeClient := fake.NewSimpleClientset()

	reconciler := &PodReconciler{
		Client:     fakeClient,
		KubeClient: fakeKubeClient,
		Scheme:     scheme,
		Engine:     analyzer.NewDiagnosticEngine(),
	}

	req := ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "default", Name: "web-0"}}

	// Reconcile older pod
	_, err := reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile old pod failed: %v", err)
	}

	oldCRName := GenerateCRName("web-0", "11111-old-uid", "nginx", 1)
	var oldCR observerv1alpha1.PodRestartHistory
	if err := fakeClient.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: oldCRName}, &oldCR); err != nil {
		t.Fatalf("failed to fetch old CR: %v", err)
	}

	// Now StatefulSet recreates pod with same name but new UID
	newPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-0",
			Namespace: "default",
			UID:       "22222-new-uid",
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:         "nginx",
					RestartCount: 1, // restarted once on the new pod instance
					LastTerminationState: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode:   1,
							Reason:     "Error",
							FinishedAt: metav1.Now(),
						},
					},
				},
			},
		},
	}

	if err := fakeClient.Update(context.Background(), newPod); err != nil {
		t.Fatalf("failed to update pod to new instance: %v", err)
	}

	// Reconcile new pod instance
	_, err = reconciler.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile new pod failed: %v", err)
	}

	newCRName := GenerateCRName("web-0", "22222-new-uid", "nginx", 1)
	var newCR observerv1alpha1.PodRestartHistory
	if err := fakeClient.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: newCRName}, &newCR); err != nil {
		t.Fatalf("failed to fetch new CR (should not be skipped due to collision): %v", err)
	}

	if oldCRName == newCRName {
		t.Fatalf("CR names collided: %s == %s", oldCRName, newCRName)
	}

	// Both CRs should exist
	var list observerv1alpha1.PodRestartHistoryList
	_ = fakeClient.List(context.Background(), &list)
	if len(list.Items) != 2 {
		t.Fatalf("expected 2 CRs, got %d", len(list.Items))
	}
}
