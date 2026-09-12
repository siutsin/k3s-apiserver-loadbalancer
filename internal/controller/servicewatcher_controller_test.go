package controller_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/siutsin/k3s-apiserver-loadbalancer/internal/controller"
)

const (
	targetServiceName      = "kubernetes"
	targetServiceNamespace = "default"
)

type errClient struct {
	client.Client
	getErr    error
	updateErr error
}

func (c errClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if c.getErr != nil {
		return c.getErr
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func (c errClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if c.updateErr != nil {
		return c.updateErr
	}
	return c.Client.Update(ctx, obj, opts...)
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	return s
}

func clusterIPService(name, namespace string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			ResourceVersion: "1",
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
		},
	}
}

func TestServiceWatcherReconciler_LoadBalancerUpdate(t *testing.T) {
	svc := clusterIPService(targetServiceName, targetServiceNamespace)
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
	reconciler := &controller.ServiceWatcherReconciler{Client: c}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: targetServiceName, Namespace: targetServiceNamespace},
	})
	require.NoError(t, err)

	updated := &corev1.Service{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{
		Name: targetServiceName, Namespace: targetServiceNamespace,
	}, updated))
	require.Equal(t, corev1.ServiceTypeLoadBalancer, updated.Spec.Type)
}

func TestServiceWatcherReconciler_GetError(t *testing.T) {
	c := errClient{
		Client: fake.NewClientBuilder().WithScheme(testScheme(t)).Build(),
		getErr: errors.New("get failed"),
	}
	reconciler := &controller.ServiceWatcherReconciler{Client: c}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: targetServiceName, Namespace: targetServiceNamespace},
	})
	require.Error(t, err)
}

func TestServiceWatcherReconciler_UpdateError(t *testing.T) {
	svc := clusterIPService(targetServiceName, targetServiceNamespace)
	c := errClient{
		Client:    fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build(),
		updateErr: errors.New("update failed"),
	}
	reconciler := &controller.ServiceWatcherReconciler{Client: c}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: targetServiceName, Namespace: targetServiceNamespace},
	})
	require.Error(t, err)
}

func TestServiceWatcherReconciler_SkipsNonTarget(t *testing.T) {
	svc := clusterIPService("other-service", "kube-system")
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
	reconciler := &controller.ServiceWatcherReconciler{Client: c}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "other-service", Namespace: "kube-system"},
	})
	require.NoError(t, err)

	unchanged := &corev1.Service{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{
		Name: "other-service", Namespace: "kube-system",
	}, unchanged))
	require.Equal(t, corev1.ServiceTypeClusterIP, unchanged.Spec.Type)
}

func TestServiceWatcherReconciler_SkipsAlreadyLoadBalancer(t *testing.T) {
	svc := clusterIPService(targetServiceName, targetServiceNamespace)
	svc.Spec.Type = corev1.ServiceTypeLoadBalancer
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
	reconciler := &controller.ServiceWatcherReconciler{Client: c}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: targetServiceName, Namespace: targetServiceNamespace},
	})
	require.NoError(t, err)
}
