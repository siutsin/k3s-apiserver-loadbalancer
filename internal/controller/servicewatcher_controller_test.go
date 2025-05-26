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

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = ginkgo.Describe("ServiceWatcher Controller", func() {
	ginkgo.Context("When reconciling a Kubernetes Service resource", func() {
		const (
			serviceName      = "kubernetes"
			serviceNamespace = "default"
		)
		ctx := context.Background()
		typeNamespacedName := types.NamespacedName{
			Name:      serviceName,
			Namespace: serviceNamespace,
		}
		ginkgo.It("should update the Service type to LoadBalancer", func() {
			ginkgo.By("Reconciling the Service resource")
			controllerReconciler := &ServiceWatcherReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			service := &corev1.Service{}
			gomega.Expect(k8sClient.Get(ctx, typeNamespacedName, service)).To(gomega.Succeed())

			ginkgo.By("verifying that the Service type is LoadBalancer")
			gomega.Expect(service.Spec.Type).To(gomega.Equal(corev1.ServiceTypeLoadBalancer))
		})
	})
})
