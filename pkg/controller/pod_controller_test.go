package controller

import (
	"context"
	"strings"
	"testing"

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
