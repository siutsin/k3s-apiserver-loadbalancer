/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ServiceWatcherReconciler reconciles a ServiceWatcher object
type ServiceWatcherReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// The ServiceWatcher objects against the actual cluster state and then
// performs operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.4/pkg/reconcile
func (r *ServiceWatcherReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("namespace", req.Namespace, "name", req.Name)
	var service corev1.Service

	if err := r.Get(ctx, req.NamespacedName, &service); err != nil {
		log.Error(err, "unable to fetch Service")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if service.Namespace == "default" && service.Name == "kubernetes" && service.Spec.Type == corev1.ServiceTypeClusterIP {
		log.Info("Service has been updated", "service", service.Name, "type", service.Spec.Type)
		originalResourceVersion := service.ResourceVersion
		service.Spec.Type = corev1.ServiceTypeLoadBalancer
		// Ensure the resource version matches to prevent race conditions and ensure consistency when
		// multiple clients try to update the same resource simultaneously
		service.ResourceVersion = originalResourceVersion
		if err := r.Update(ctx, &service); err != nil {
			log.Error(err, "failed to update Service to LoadBalancer")
			return ctrl.Result{}, err
		}
		log.Info("Service has been updated to LoadBalancer", "service", service.Name, "type", service.Spec.Type)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ServiceWatcherReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Complete(r)
}
