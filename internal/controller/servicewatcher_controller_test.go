package controller_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/siutsin/k3s-apiserver-loadbalancer/internal/controller"
	"github.com/siutsin/k3s-apiserver-loadbalancer/internal/controller/mocks"
	"go.uber.org/mock/gomock"
)

// newTestScheme creates a runtime.Scheme with core and client-go types registered.
func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = clientgoscheme.AddToScheme(s)
	return s
}

func TestServiceWatcherReconciler_LoadBalancerUpdate(t *testing.T) {
	mockCtrl := gomock.NewController(t)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "kubernetes",
			Namespace:       "default",
			ResourceVersion: "1",
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
		},
	}

	mockClient := mocks.NewMockClient(mockCtrl)
	mockClient.EXPECT().
		Get(gomock.Any(), types.NamespacedName{Name: "kubernetes", Namespace: "default"}, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
			*obj.(*corev1.Service) = *svc
			return nil
		})
	mockClient.EXPECT().
		Update(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, obj client.Object, _ ...client.UpdateOption) error {
			updated := obj.(*corev1.Service)
			assert.Equal(t, corev1.ServiceTypeLoadBalancer, updated.Spec.Type)
			return nil
		})

	reconciler := &controller.ServiceWatcherReconciler{
		Client: mockClient,
		Scheme: newTestScheme(),
	}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "kubernetes",
			Namespace: "default",
		},
	})

	require.NoError(t, err)
}

func TestServiceWatcherReconciler_GetError(t *testing.T) {
	mockCtrl := gomock.NewController(t)

	errNotFound := errors.New("not found")

	mockClient := mocks.NewMockClient(mockCtrl)
	mockClient.EXPECT().
		Get(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(errNotFound)

	reconciler := &controller.ServiceWatcherReconciler{
		Client: mockClient,
		Scheme: newTestScheme(),
	}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "kubernetes",
			Namespace: "default",
		},
	})

	require.Error(t, err)
}

func TestServiceWatcherReconciler_UpdateError(t *testing.T) {
	mockCtrl := gomock.NewController(t)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "kubernetes",
			Namespace:       "default",
			ResourceVersion: "1",
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
		},
	}

	errUpdate := errors.New("update failed")

	mockClient := mocks.NewMockClient(mockCtrl)
	mockClient.EXPECT().
		Get(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
			*obj.(*corev1.Service) = *svc
			return nil
		})
	mockClient.EXPECT().
		Update(gomock.Any(), gomock.Any()).
		Return(errUpdate)

	reconciler := &controller.ServiceWatcherReconciler{
		Client: mockClient,
		Scheme: newTestScheme(),
	}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "kubernetes",
			Namespace: "default",
		},
	})

	require.Error(t, err)
}

func TestServiceWatcherReconciler_SkipsNonTarget(t *testing.T) {
	mockCtrl := gomock.NewController(t)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "other-service",
			Namespace:       "kube-system",
			ResourceVersion: "1",
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
		},
	}

	mockClient := mocks.NewMockClient(mockCtrl)
	mockClient.EXPECT().
		Get(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
			*obj.(*corev1.Service) = *svc
			return nil
		})
	// No Update call expected; gomock will fail if Update is called.

	reconciler := &controller.ServiceWatcherReconciler{
		Client: mockClient,
		Scheme: newTestScheme(),
	}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "other-service",
			Namespace: "kube-system",
		},
	})

	require.NoError(t, err)
}

func TestServiceWatcherReconciler_SkipsAlreadyLoadBalancer(t *testing.T) {
	mockCtrl := gomock.NewController(t)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "kubernetes",
			Namespace:       "default",
			ResourceVersion: "1",
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
		},
	}

	mockClient := mocks.NewMockClient(mockCtrl)
	mockClient.EXPECT().
		Get(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
			*obj.(*corev1.Service) = *svc
			return nil
		})
	// No Update call expected.

	reconciler := &controller.ServiceWatcherReconciler{
		Client: mockClient,
		Scheme: newTestScheme(),
	}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "kubernetes",
			Namespace: "default",
		},
	})

	require.NoError(t, err)
}
