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

package datapath

import "testing"

// TestPodHookNeedsReconcile locks the three states the live reconciler must
// distinguish: missing, present too early, and already last. The missing case
// is the recovery path used after another TCX owner replaces either direction.
func TestPodHookNeedsReconcile(t *testing.T) {
	for _, tc := range []struct {
		name     string
		own      int
		programs int
		first    bool
		want     bool
	}{
		{name: "only hook missing", own: -1, programs: 0, want: true},
		{name: "last missing", own: -1, programs: 2, want: true},
		{name: "last too early", own: 0, programs: 3, want: true},
		{name: "already last", own: 2, programs: 3, want: false},
		{name: "first missing", own: -1, programs: 2, first: true, want: true},
		{name: "first too late", own: 2, programs: 3, first: true, want: true},
		{name: "already first", own: 0, programs: 3, first: true, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := podHookNeedsReconcile(tc.own, tc.programs, tc.first)
			if got != tc.want {
				t.Fatalf("needs reconcile = %v, want %v", got, tc.want)
			}
		})
	}
}
