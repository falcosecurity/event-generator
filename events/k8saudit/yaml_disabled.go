// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.
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

package k8saudit

// disabled items will be registered with events.WithDisabled() option
var disabled = map[string]bool{
	"cluster-role-with-pod-exec-created.yaml":               true,
	"cluster-role-with-wildcard-created.yaml":               true,
	"cluster-role-with-write-privileges-created.yaml":       true,
	"create-disallowed-pod.yaml":                            true,
	"create-host-network-pod.yaml":                          true,
	"create-modify-configmap-with-private-credentials.yaml": true,
	"create-node-port-service.yaml":                         true,
	"create-privileged-pod.yaml":                            true,
	"create-sensitive-mount-pod.yaml":                       true,
	"k8s-config-map-created.yaml":                           true,
	"k8s-deployment-created.yaml":                           true,
	"k8s-serviceaccount-created.yaml":                       true,
	"k8s-service-created.yaml":                              true,
}
