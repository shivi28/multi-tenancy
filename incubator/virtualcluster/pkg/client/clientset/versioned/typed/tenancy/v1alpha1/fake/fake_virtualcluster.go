/*
Copyright The Kubernetes Authors.

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

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1alpha1 "github.com/multi-tenancy/incubator/virtualcluster/pkg/apis/tenancy/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeVirtualclusters implements VirtualclusterInterface
type FakeVirtualclusters struct {
	Fake *FakeTenancyV1alpha1
	ns   string
}

var virtualclustersResource = schema.GroupVersionResource{Group: "tenancy.x-k8s.io", Version: "v1alpha1", Resource: "virtualclusters"}

var virtualclustersKind = schema.GroupVersionKind{Group: "tenancy.x-k8s.io", Version: "v1alpha1", Kind: "Virtualcluster"}

// Get takes name of the virtualcluster, and returns the corresponding virtualcluster object, and an error if there is any.
func (c *FakeVirtualclusters) Get(name string, options v1.GetOptions) (result *v1alpha1.Virtualcluster, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(virtualclustersResource, c.ns, name), &v1alpha1.Virtualcluster{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Virtualcluster), err
}

// List takes label and field selectors, and returns the list of Virtualclusters that match those selectors.
func (c *FakeVirtualclusters) List(opts v1.ListOptions) (result *v1alpha1.VirtualclusterList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(virtualclustersResource, virtualclustersKind, c.ns, opts), &v1alpha1.VirtualclusterList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.VirtualclusterList{ListMeta: obj.(*v1alpha1.VirtualclusterList).ListMeta}
	for _, item := range obj.(*v1alpha1.VirtualclusterList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested virtualclusters.
func (c *FakeVirtualclusters) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(virtualclustersResource, c.ns, opts))

}

// Create takes the representation of a virtualcluster and creates it.  Returns the server's representation of the virtualcluster, and an error, if there is any.
func (c *FakeVirtualclusters) Create(virtualcluster *v1alpha1.Virtualcluster) (result *v1alpha1.Virtualcluster, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(virtualclustersResource, c.ns, virtualcluster), &v1alpha1.Virtualcluster{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Virtualcluster), err
}

// Update takes the representation of a virtualcluster and updates it. Returns the server's representation of the virtualcluster, and an error, if there is any.
func (c *FakeVirtualclusters) Update(virtualcluster *v1alpha1.Virtualcluster) (result *v1alpha1.Virtualcluster, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(virtualclustersResource, c.ns, virtualcluster), &v1alpha1.Virtualcluster{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Virtualcluster), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeVirtualclusters) UpdateStatus(virtualcluster *v1alpha1.Virtualcluster) (*v1alpha1.Virtualcluster, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(virtualclustersResource, "status", c.ns, virtualcluster), &v1alpha1.Virtualcluster{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Virtualcluster), err
}

// Delete takes name of the virtualcluster and deletes it. Returns an error if one occurs.
func (c *FakeVirtualclusters) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(virtualclustersResource, c.ns, name), &v1alpha1.Virtualcluster{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeVirtualclusters) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(virtualclustersResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &v1alpha1.VirtualclusterList{})
	return err
}

// Patch applies the patch and returns the patched virtualcluster.
func (c *FakeVirtualclusters) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.Virtualcluster, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(virtualclustersResource, c.ns, name, pt, data, subresources...), &v1alpha1.Virtualcluster{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.Virtualcluster), err
}
