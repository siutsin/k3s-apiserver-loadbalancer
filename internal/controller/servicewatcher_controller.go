package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ServiceWatcherReconciler watches Services and sets default/kubernetes to LoadBalancer.
type ServiceWatcherReconciler struct {
	client.Client
}

// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;update;patch

func (r *ServiceWatcherReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("namespace", req.Namespace, "name", req.Name)
	var service corev1.Service

	if err := r.Get(ctx, req.NamespacedName, &service); err != nil {
		log.Error(err, "unable to fetch Service")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if service.Namespace != "default" || service.Name != "kubernetes" || service.Spec.Type != corev1.ServiceTypeClusterIP {
		return ctrl.Result{}, nil
	}

	service.Spec.Type = corev1.ServiceTypeLoadBalancer
	// Update keeps the fetched resource version, so Kubernetes rejects stale writes with a conflict.
	if err := r.Update(ctx, &service); err != nil {
		log.Error(err, "failed to update Service to LoadBalancer")
		return ctrl.Result{}, err
	}
	log.Info("Service has been updated to LoadBalancer", "service", service.Name, "type", service.Spec.Type)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ServiceWatcherReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Complete(r)
}
