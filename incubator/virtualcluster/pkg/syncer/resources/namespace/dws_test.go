/*
Copyright 2020 The Kubernetes Authors.

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

package namespace

import (
	"fmt"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	core "k8s.io/client-go/testing"

	"sigs.k8s.io/multi-tenancy/incubator/virtualcluster/pkg/apis/tenancy/v1alpha1"
	"sigs.k8s.io/multi-tenancy/incubator/virtualcluster/pkg/syncer/constants"
	"sigs.k8s.io/multi-tenancy/incubator/virtualcluster/pkg/syncer/conversion"
	"sigs.k8s.io/multi-tenancy/incubator/virtualcluster/pkg/syncer/util/featuregate"
	util "sigs.k8s.io/multi-tenancy/incubator/virtualcluster/pkg/syncer/util/test"
	utilconst "sigs.k8s.io/multi-tenancy/incubator/virtualcluster/pkg/util/constants"
)

func tenantNamespace(name, uid string) *v1.Namespace {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			UID:  types.UID(uid),
		},
	}
	if featuregate.DefaultFeatureGate.Enabled(featuregate.SuperClusterPooling) {
		ns.Annotations = map[string]string{
			utilconst.LabelScheduledPlacements: fmt.Sprintf("{\"%s\":1}", utilconst.SuperClusterID),
		}
	}
	return ns
}

func applyAnnotationToNS(ns *v1.Namespace, k, v string) *v1.Namespace {
	anno := ns.GetAnnotations()
	if anno == nil {
		anno = make(map[string]string)
	}
	anno[k] = v
	ns.SetAnnotations(anno)
	return ns
}

func superNamespace(name, uid, clusterKey string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Annotations: map[string]string{
				constants.LabelUID:         uid,
				constants.LabelCluster:     clusterKey,
				constants.LabelNamespace:   "default",
				constants.LabelVCName:      "test",
				constants.LabelVCNamespace: "tenant-1",
				constants.LabelVCUID:       "7374a172-c35d-45b1-9c8e-bf5c5b614937",
			},
		},
	}
}

func unknownNamespace(name, uid string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			UID:  types.UID(uid),
		},
	}
}

func TestDWNamespaceCreation(t *testing.T) {
	testTenant := &v1alpha1.VirtualCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "tenant-1",
			UID:       "7374a172-c35d-45b1-9c8e-bf5c5b614937",
		},
		Spec: v1alpha1.VirtualClusterSpec{},
		Status: v1alpha1.VirtualClusterStatus{
			Phase: v1alpha1.ClusterRunning,
		},
	}

	defaultNSName := "default"
	defaultClusterKey := conversion.ToClusterKey(testTenant)
	defaultSuperNSName := conversion.ToSuperMasterNamespace(defaultClusterKey, defaultNSName)

	testcases := map[string]struct {
		ExistingObjectInSuper  []runtime.Object
		ExistingObjectInTenant *v1.Namespace

		ExpectedCreatedNamespace []string
		ExpectedError            string
	}{
		"new namespace": {
			ExistingObjectInSuper:    []runtime.Object{},
			ExistingObjectInTenant:   tenantNamespace(defaultNSName, "12345"),
			ExpectedCreatedNamespace: []string{defaultSuperNSName},
		},
		"new namespace but already exists": {
			ExistingObjectInSuper: []runtime.Object{
				superNamespace(defaultSuperNSName, "12345", defaultClusterKey),
			},
			ExistingObjectInTenant:   tenantNamespace(defaultNSName, "12345"),
			ExpectedCreatedNamespace: []string{},
			ExpectedError:            "",
		},
		"new namespace but existing different uid one": {
			ExistingObjectInSuper: []runtime.Object{
				superNamespace(defaultSuperNSName, "123456", defaultClusterKey),
			},
			ExistingObjectInTenant:   tenantNamespace(defaultNSName, "12345"),
			ExpectedCreatedNamespace: []string{},
			ExpectedError:            "delegated UID is different",
		},
	}

	for k, tc := range testcases {
		t.Run(k, func(t *testing.T) {
			actions, reconcileErr, err := util.RunDownwardSync(NewNamespaceController,
				testTenant,
				tc.ExistingObjectInSuper,
				[]runtime.Object{tc.ExistingObjectInTenant},
				tc.ExistingObjectInTenant,
				nil)
			if err != nil {
				t.Errorf("%s: error running downward sync: %v", k, err)
				return
			}

			if reconcileErr != nil {
				if tc.ExpectedError == "" {
					t.Errorf("expected no error, but got \"%v\"", reconcileErr)
				} else if !strings.Contains(reconcileErr.Error(), tc.ExpectedError) {
					t.Errorf("expected error msg \"%s\", but got \"%v\"", tc.ExpectedError, reconcileErr)
				}
			} else {
				if tc.ExpectedError != "" {
					t.Errorf("expected error msg \"%s\", but got empty", tc.ExpectedError)
				}
			}

			if len(tc.ExpectedCreatedNamespace) != len(actions) {
				t.Errorf("%s: Expected to create namespace %#v. Actual actions were: %#v", k, tc.ExpectedCreatedNamespace, actions)
				return
			}
			for i, expectedName := range tc.ExpectedCreatedNamespace {
				action := actions[i]
				if !action.Matches("create", "namespaces") {
					t.Errorf("%s: Unexpected action %s", k, action)
				}
				createdNS := action.(core.CreateAction).GetObject().(*v1.Namespace)
				if createdNS.Name != expectedName {
					t.Errorf("%s: Expected %s to be created, got %s", k, expectedName, createdNS.Name)
				}
			}
		})
	}
}

func TestDWNamespaceDeletion(t *testing.T) {
	testTenant := &v1alpha1.VirtualCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "tenant-1",
			UID:       "7374a172-c35d-45b1-9c8e-bf5c5b614937",
		},
		Spec: v1alpha1.VirtualClusterSpec{},
		Status: v1alpha1.VirtualClusterStatus{
			Phase: v1alpha1.ClusterRunning,
		},
	}

	defaultNSName := "default"
	defaultClusterKey := conversion.ToClusterKey(testTenant)
	defaultSuperNSName := conversion.ToSuperMasterNamespace(defaultClusterKey, defaultNSName)

	testcases := map[string]struct {
		ExistingObjectInSuper []runtime.Object
		EnqueueObject         *v1.Namespace

		ExpectedDeletedNamespace []string
		ExpectedError            string
	}{
		"delete namespace": {
			ExistingObjectInSuper: []runtime.Object{
				superNamespace(defaultSuperNSName, "12345", defaultClusterKey),
			},
			EnqueueObject:            tenantNamespace(defaultNSName, "12345"),
			ExpectedDeletedNamespace: []string{defaultSuperNSName},
		},
		"delete namespace but already gone": {
			ExistingObjectInSuper:    []runtime.Object{},
			EnqueueObject:            tenantNamespace(defaultNSName, "12345"),
			ExpectedDeletedNamespace: []string{},
			ExpectedError:            "",
		},
		"delete namespace but existing different uid one": {
			ExistingObjectInSuper: []runtime.Object{
				superNamespace(defaultSuperNSName, "123456", defaultClusterKey),
			},
			EnqueueObject:            tenantNamespace(defaultNSName, "12345"),
			ExpectedDeletedNamespace: []string{},
			ExpectedError:            "delegated UID is different",
		},
	}

	for k, tc := range testcases {
		t.Run(k, func(t *testing.T) {
			actions, reconcileErr, err := util.RunDownwardSync(NewNamespaceController, testTenant, tc.ExistingObjectInSuper, nil, tc.EnqueueObject, nil)
			if err != nil {
				t.Errorf("%s: error running downward sync: %v", k, err)
				return
			}

			if reconcileErr != nil {
				if tc.ExpectedError == "" {
					t.Errorf("expected no error, but got \"%v\"", reconcileErr)
				} else if !strings.Contains(reconcileErr.Error(), tc.ExpectedError) {
					t.Errorf("expected error msg \"%s\", but got \"%v\"", tc.ExpectedError, reconcileErr)
				}
			} else {
				if tc.ExpectedError != "" {
					t.Errorf("expected error msg \"%s\", but got empty", tc.ExpectedError)
				}
			}

			if len(tc.ExpectedDeletedNamespace) != len(actions) {
				t.Errorf("%s: Expected to delete namespace %#v. Actual actions were: %#v", k, tc.ExpectedDeletedNamespace, actions)
				return
			}
			for i, expectedName := range tc.ExpectedDeletedNamespace {
				action := actions[i]
				if !action.Matches("delete", "namespaces") {
					t.Errorf("%s: Unexpected action %s", k, action)
				}
				deleteNS := action.(core.DeleteAction).GetName()
				if deleteNS != expectedName {
					t.Errorf("%s: Expected %s to be created, got %s", k, expectedName, deleteNS)
				}
			}
		})
	}
}
