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

package apigate

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	discoveryfake "k8s.io/client-go/discovery/fake"
	clienttesting "k8s.io/client-go/testing"
)

var sdnGV = schema.GroupVersion{Group: "sdn.cozystack.io", Version: "v1alpha1"}

func fakeDiscovery(lists ...*metav1.APIResourceList) *discoveryfake.FakeDiscovery {
	return &discoveryfake.FakeDiscovery{Fake: &clienttesting.Fake{Resources: lists}}
}

func resourceList(gv schema.GroupVersion, names ...string) *metav1.APIResourceList {
	l := &metav1.APIResourceList{GroupVersion: gv.String()}
	for _, n := range names {
		l.APIResources = append(l.APIResources, metav1.APIResource{Name: n})
	}
	return l
}

func TestDiscoveryProber(t *testing.T) {
	tests := []struct {
		name      string
		lists     []*metav1.APIResourceList
		want      []string
		wantSrvd  bool
		wantErrIs error
	}{
		{
			// The bootstrap window: no APIService for the group at all. This
			// must read as "not served", NOT as an error — it is the expected
			// state for the whole window and would otherwise log on every tick.
			name:     "group absent",
			lists:    nil,
			want:     []string{"vpcs"},
			wantSrvd: false,
		},
		{
			name:     "group served with the required resources",
			lists:    []*metav1.APIResourceList{resourceList(sdnGV, "vpcs", "ports")},
			want:     []string{"vpcs", "ports"},
			wantSrvd: true,
		},
		{
			// A half-registered apiserver: the group answers but a kind this
			// process watches is missing. Starting its controller now would
			// hang exactly as an absent group does.
			name:     "group served but a required resource is missing",
			lists:    []*metav1.APIResourceList{resourceList(sdnGV, "vpcs")},
			want:     []string{"vpcs", "ports"},
			wantSrvd: false,
		},
		{
			name:     "no required resources named: any resource suffices",
			lists:    []*metav1.APIResourceList{resourceList(sdnGV, "vpcs")},
			want:     nil,
			wantSrvd: true,
		},
		{
			name:     "group answers with an empty resource list",
			lists:    []*metav1.APIResourceList{resourceList(sdnGV)},
			want:     nil,
			wantSrvd: false,
		},
		{
			// A different group being served must not open this gate.
			name:     "only another group is served",
			lists:    []*metav1.APIResourceList{resourceList(schema.GroupVersion{Group: "local.sdn.cozystack.io", Version: "v1alpha1"}, "fabricips")},
			want:     []string{"vpcs"},
			wantSrvd: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &DiscoveryProber{Client: fakeDiscovery(tc.lists...), GV: sdnGV, Resources: tc.want}
			got, err := p.Served(t.Context())
			if err != nil {
				t.Fatalf("Served() error = %v", err)
			}
			if got != tc.wantSrvd {
				t.Errorf("Served() = %v, want %v", got, tc.wantSrvd)
			}
		})
	}
}

func TestDiscoveryProberReportsNonNotFoundErrors(t *testing.T) {
	// A proxied 503 (APIService present, backend down) is a real error worth
	// logging once — but still "not served", never fatal.
	d := fakeDiscovery()
	boom := errors.New("service unavailable")
	d.Fake.PrependReactor("get", "*", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, boom
	})

	p := &DiscoveryProber{Client: d, GV: sdnGV}
	served, err := p.Served(t.Context())
	if served {
		t.Errorf("Served() = true on a discovery error, want false")
	}
	if !errors.Is(err, boom) {
		t.Errorf("Served() error = %v, want %v", err, boom)
	}
}

// scriptedProber returns the scripted answers in order, repeating the last one.
type scriptedProber struct {
	mu      sync.Mutex
	answers []bool
	calls   int
}

func (s *scriptedProber) Served(context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := min(s.calls, len(s.answers)-1)
	s.calls++
	return s.answers[i], nil
}

func (s *scriptedProber) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// runGate starts g and returns a stop func; it fails the test if Start errors.
func runGate(t *testing.T, g *Gate) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- g.Start(ctx) }()
	return func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Gate.Start() = %v, want nil", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Gate.Start() did not return after cancellation")
		}
	}
}

func TestGateRegistersWhenTheGroupAppears(t *testing.T) {
	var registered atomic32
	prober := &scriptedProber{answers: []bool{false, false, true}}
	g := &Gate{
		Name:     sdnGV.String(),
		Prober:   prober,
		Interval: time.Millisecond,
		Log:      logr.Discard(),
		Register: func(context.Context) error { registered.inc(); return nil },
	}
	stop := runGate(t, g)
	defer stop()

	waitFor(t, func() bool { return registered.get() == 1 }, "controllers to be registered")

	// It must keep polling after registration (so a group that vanishes is
	// still observable) and must never register a second time.
	before := prober.callCount()
	waitFor(t, func() bool { return prober.callCount() > before }, "polling to continue after registration")
	if got := registered.get(); got != 1 {
		t.Errorf("Register called %d times, want exactly 1", got)
	}
}

func TestGateRegistersImmediatelyWhenTheGroupIsAlreadyServed(t *testing.T) {
	// The healthy-cluster path: no behaviour change, the controllers come up at
	// startup rather than one poll interval later.
	var registered atomic32
	g := &Gate{
		Name:   sdnGV.String(),
		Prober: &scriptedProber{answers: []bool{true}},
		// An interval long enough that a second tick cannot be what registers.
		Interval: time.Hour,
		Log:      logr.Discard(),
		Register: func(context.Context) error { registered.inc(); return nil },
	}
	stop := runGate(t, g)
	defer stop()

	waitFor(t, func() bool { return registered.get() == 1 }, "controllers to be registered on the first probe")
}

func TestGateSurvivesTheGroupDisappearing(t *testing.T) {
	// Served, then gone. The controllers cannot be un-registered and the Gate
	// must not turn the disappearance into a process exit.
	var registered atomic32
	prober := &scriptedProber{answers: []bool{true, false}}
	g := &Gate{
		Name:     sdnGV.String(),
		Prober:   prober,
		Interval: time.Millisecond,
		Log:      logr.Discard(),
		Register: func(context.Context) error { registered.inc(); return nil },
	}
	stop := runGate(t, g)

	waitFor(t, func() bool { return prober.callCount() >= 5 }, "the gate to keep polling after the group vanished")
	if got := registered.get(); got != 1 {
		t.Errorf("Register called %d times, want exactly 1", got)
	}
	stop() // asserts Start returned nil, i.e. the vanished group was not fatal
}

func TestGateReturnsRegistrationFailure(t *testing.T) {
	// A SetupWithManager failure is a wiring bug, not an absent API: it is
	// fatal, exactly as it was when registration happened before mgr.Start.
	boom := errors.New("controller was started more than once")
	g := &Gate{
		Name:     sdnGV.String(),
		Prober:   &scriptedProber{answers: []bool{true}},
		Interval: time.Millisecond,
		Log:      logr.Discard(),
		Register: func(context.Context) error { return boom },
	}

	err := g.Start(t.Context())
	if !errors.Is(err, boom) {
		t.Fatalf("Gate.Start() = %v, want it to wrap %v", err, boom)
	}
}

func TestGateNeedsNoLeaderElection(t *testing.T) {
	// Polling while standby means the gated set is ready the moment leadership
	// is acquired; the controllers it adds carry their own requirement.
	if (&Gate{}).NeedLeaderElection() {
		t.Error("NeedLeaderElection() = true, want false")
	}
}

// --- tiny helpers ---------------------------------------------------------

type atomic32 struct {
	mu sync.Mutex
	n  int
}

func (a *atomic32) inc() { a.mu.Lock(); a.n++; a.mu.Unlock() }
func (a *atomic32) get() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestGateGaugesTrackTheState(t *testing.T) {
	// The pair must be able to disagree: served=0 with started=1 is "the
	// apiserver was removed under running controllers", the state worth
	// alerting on, and an absent series would not say that.
	const group = "gauge-test.cozystack.io/v1alpha1"
	prober := &scriptedProber{answers: []bool{false, true, false}}
	g := &Gate{
		Name:     group,
		Prober:   prober,
		Interval: time.Millisecond,
		Log:      logr.Discard(),
		Register: func(context.Context) error { return nil },
	}
	stop := runGate(t, g)
	defer stop()

	waitFor(t, func() bool {
		return testutil.ToFloat64(apiGroupServed.WithLabelValues(group)) == 0 &&
			testutil.ToFloat64(apiGroupControllersStarted.WithLabelValues(group)) == 1
	}, "served=0 started=1 after the group vanished under started controllers")
}
