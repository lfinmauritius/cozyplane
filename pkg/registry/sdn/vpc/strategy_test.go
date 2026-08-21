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

package vpc

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
)

func newStrategyForTest(t *testing.T) vpcStrategy {
	t.Helper()
	scheme := runtime.NewScheme()
	install.Install(scheme)
	return NewStrategy(scheme)
}

func vpcWith(cidrs []string, mtu int32) *sdn.VPC {
	return &sdn.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: "v", Namespace: "team-a"},
		Spec:       sdn.VPCSpec{CIDRs: cidrs, MTU: mtu},
	}
}

func TestValidateVPCSpec(t *testing.T) {
	s := newStrategyForTest(t)
	cases := []struct {
		name    string
		obj     *sdn.VPC
		wantErr bool
	}{
		{"v4", vpcWith([]string{"10.10.0.0/16"}, 0), false},
		{"v6", vpcWith([]string{"fd00:a::/64"}, 0), false},
		{"dual-stack", vpcWith([]string{"10.10.0.0/16", "fd00:a::/64"}, 1400), false},

		// The case that made a VPC report Ready and host nothing.
		{"no CIDR", vpcWith(nil, 0), true},
		{"empty CIDR list", vpcWith([]string{}, 0), true},
		{"garbage CIDR", vpcWith([]string{"not-a-cidr"}, 0), true},
		{"bare address, no prefix", vpcWith([]string{"10.10.0.1"}, 0), true},
		{"one good one bad", vpcWith([]string{"10.10.0.0/16", "nope"}, 0), true},

		// Non-canonical: silently means 10.10.0.0/16 to everything downstream.
		{"host bits set", vpcWith([]string{"10.10.0.5/16"}, 0), true},

		{"mtu too small", vpcWith([]string{"10.10.0.0/16"}, 100), true},
		{"mtu too large", vpcWith([]string{"10.10.0.0/16"}, 70000), true},
		{"mtu negative", vpcWith([]string{"10.10.0.0/16"}, -1), true},
		{"mtu zero means default", vpcWith([]string{"10.10.0.0/16"}, 0), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := s.Validate(context.Background(), c.obj)
			if c.wantErr && len(errs) == 0 {
				t.Fatal("want rejected, got accepted")
			}
			if !c.wantErr && len(errs) != 0 {
				t.Fatalf("want accepted, got %v", errs)
			}
		})
	}
}

// An object stored before this validation existed must stay editable, or an
// operator cannot even repair it. Only a CHANGED spec is re-validated.
func TestValidateUpdateRatchets(t *testing.T) {
	s := newStrategyForTest(t)
	legacy := vpcWith([]string{"10.10.0.5/16"}, 0) // non-canonical, already stored

	unchanged := legacy.DeepCopy()
	unchanged.Labels = map[string]string{"team": "a"}
	if errs := s.ValidateUpdate(context.Background(), unchanged, legacy); len(errs) != 0 {
		t.Fatalf("editing a label on a legacy VPC should be allowed, got %v", errs)
	}

	repaired := legacy.DeepCopy()
	repaired.Spec.CIDRs = []string{"10.10.0.0/16"}
	if errs := s.ValidateUpdate(context.Background(), repaired, legacy); len(errs) != 0 {
		t.Fatalf("repairing the CIDR should be allowed, got %v", errs)
	}

	worse := legacy.DeepCopy()
	worse.Spec.CIDRs = []string{"still-not-a-cidr"}
	if errs := s.ValidateUpdate(context.Background(), worse, legacy); len(errs) == 0 {
		t.Fatal("changing the CIDR to garbage should be rejected")
	}
}
