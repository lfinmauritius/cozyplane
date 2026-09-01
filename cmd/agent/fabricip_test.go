/*
Copyright 2026 The Cozyplane Authors.

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

package main

import (
	"fmt"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func nodeWithIP(name, ip string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: ip}},
		},
	}
}

func TestNodeIPIndexRoundTrip(t *testing.T) {
	idx := newNodeIPIndex()
	idx.set(nodeWithIP("node-a", "10.0.0.1"))

	if got := idx.get("node-a"); got == nil || got.String() != "10.0.0.1" {
		t.Fatalf("get(node-a) = %v, want 10.0.0.1", got)
	}
	if got := idx.get("node-missing"); got != nil {
		t.Fatalf("get(node-missing) = %v, want nil", got)
	}
	// A node with no InternalIP records nothing rather than a nil entry.
	idx.set(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-b"}})
	if got := idx.get("node-b"); got != nil {
		t.Fatalf("get(node-b) = %v, want nil for a node with no InternalIP", got)
	}
}

// TestNodeIPIndexConcurrentAccess reproduces the shape that crashed the agent:
// the Node informer writes while the FabricIP informer and the sdn informers
// read, each on its own goroutine. Unguarded this is not a stale read but a
// runtime FATAL ("concurrent map read and map write") that takes the node's
// datapath manager down. Run under -race to catch a regression before the
// fatal does.
func TestNodeIPIndexConcurrentAccess(t *testing.T) {
	idx := newNodeIPIndex()
	const workers, iterations = 8, 500

	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(2)
		go func(w int) { // the Node informer
			defer wg.Done()
			for i := range iterations {
				idx.set(nodeWithIP(fmt.Sprintf("node-%d", w), fmt.Sprintf("10.0.%d.%d", w, i%256)))
			}
		}(w)
		go func(w int) { // the FabricIP / sdn informers
			defer wg.Done()
			for range iterations {
				_ = idx.get(fmt.Sprintf("node-%d", w))
			}
		}(w)
	}
	wg.Wait()

	for w := range workers {
		if got := idx.get(fmt.Sprintf("node-%d", w)); got == nil {
			t.Fatalf("node-%d lost its address under concurrent access", w)
		}
	}
}
