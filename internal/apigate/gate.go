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

// Package apigate defers a set of controllers until the API group they watch is
// actually served.
//
// Why this exists: since the API-group split (docs/api-groups.md) the tenant
// kinds — VPC, Port, SecurityGroup, … — live in `sdn.cozystack.io`, which is
// served *only* by the cozyplane aggregated apiserver. That apiserver needs
// cert-manager, an EtcdCluster and a StorageClass, all of which are ordinary
// default-network pods, so they need the CNI first. Every fresh install
// therefore has a window in which cozyplane's own controller is running and its
// aggregated group does not exist yet.
//
// Registering a controller for an unserved kind is fatal in controller-runtime:
// source.Kind loops on "no matches for kind", the cache never syncs, the
// per-source CacheSyncTimeout fires, Controller.Start returns that error and the
// manager exits. The process then crashloops for the whole window — taking down
// FabricIP GC, which needs nothing but the kube API, with it.
//
// A Gate closes that window by polling discovery and calling Register only once
// the group/version answers, adding those controllers to the *already running*
// manager. Until then the manager runs degraded: everything ungated is live.
package apigate

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/discovery"
)

// DefaultInterval is how often an absent group is re-probed. Discovery for an
// aggregated group is a proxied round-trip to the extension apiserver, so this
// is deliberately unhurried: the wait is minutes long (cert-manager, etcd and a
// StorageClass have to land first) and nobody is watching the seconds.
const DefaultInterval = 15 * time.Second

// Prober answers whether the gated API surface is currently served.
type Prober interface {
	// Served reports whether the surface is usable right now. A transport or
	// server error is reported as (false, err): not served, and the reason is
	// worth logging once.
	Served(ctx context.Context) (bool, error)
}

// DiscoveryProber checks a GroupVersion through the discovery API.
//
// It asks for the group's resource list rather than merely for the group's
// presence in /apis, because those differ in exactly the case that matters: an
// APIService whose backend Deployment is not up yet still advertises its group,
// and starting informers against it would fail the same way an absent group
// does. Fetching the resource list is proxied to the backend, so it succeeds
// only when the backend actually answers.
type DiscoveryProber struct {
	Client discovery.DiscoveryInterface
	GV     schema.GroupVersion
	// Resources, if set, must all be present in the group's resource list.
	// Guards against a half-registered server advertising the group before its
	// registries are installed.
	Resources []string
}

// Served implements Prober.
func (p *DiscoveryProber) Served(ctx context.Context) (bool, error) {
	list, err := p.Client.ServerResourcesForGroupVersion(p.GV.String())
	switch {
	case apierrors.IsNotFound(err):
		// The group/version is simply not registered — the bootstrap window.
		// Not an error worth reporting; it is the expected steady state until
		// the apiserver lands.
		return false, nil
	case err != nil:
		return false, err
	case list == nil:
		return false, nil
	}

	if len(p.Resources) == 0 {
		return len(list.APIResources) > 0, nil
	}

	have := sets.New[string]()
	for _, r := range list.APIResources {
		have.Insert(r.Name)
	}
	for _, want := range p.Resources {
		if !have.Has(want) {
			return false, nil
		}
	}
	return true, nil
}

// Gate is a manager Runnable that registers a set of controllers the first time
// its Prober reports the API served, and never registers them twice.
//
// It keeps polling after registration: the controllers cannot be un-registered,
// but the group going away again is worth a log line and a metric, and the Gate
// must not be the thing that kills the process when it does. A vanished
// aggregated API only makes the running informers' relists fail, which
// client-go retries — it is not fatal on its own.
type Gate struct {
	// Name identifies the gated surface in logs and metrics, e.g.
	// "sdn.cozystack.io/v1alpha1".
	Name   string
	Prober Prober
	// Register adds the gated controllers to the manager. controller-runtime
	// supports Add after Start: the runnable group starts them immediately.
	//
	// A failure here is a wiring bug, not an absent API, and is returned to the
	// manager as fatal — exactly as an early SetupWithManager failure is. It is
	// never retried, because a partially-registered set cannot be registered
	// again ("controller was started more than once").
	Register func(ctx context.Context) error
	// Interval between probes; DefaultInterval when zero.
	Interval time.Duration
	Log      logr.Logger
}

// NeedLeaderElection is false: the Gate itself neither reads nor writes cluster
// state, and the controllers it registers carry their own leader-election
// requirement. Polling while standby means the set is ready the moment
// leadership is acquired.
func (g *Gate) NeedLeaderElection() bool { return false }

// Start implements manager.Runnable. It returns nil only when ctx is done.
func (g *Gate) Start(ctx context.Context) error {
	interval := g.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}

	var (
		registered bool
		// known is nil until the first probe, so the first observation always
		// logs — degraded or not, the state is stated once at startup.
		known *bool
	)

	for {
		served, err := g.Prober.Served(ctx)
		if err != nil {
			// Probe failures are transient by assumption (API server restart,
			// a proxied 503). Treat as not-served and try again.
			g.Log.V(1).Info("api group discovery probe failed", "group", g.Name, "err", err)
		}
		setServed(g.Name, served)

		if known == nil || *known != served {
			switch {
			case served && registered:
				g.Log.Info("gated API group is served again", "group", g.Name)
			case served:
				g.Log.Info("gated API group is served; starting its controllers", "group", g.Name)
			case registered:
				g.Log.Info("gated API group stopped being served; its controllers stay up and will resync when it returns",
					"group", g.Name)
			default:
				g.Log.Info("gated API group is not served yet; running DEGRADED without its controllers",
					"group", g.Name, "retryInterval", interval.String())
			}
			known = &served
		}

		if served && !registered {
			if err := g.Register(ctx); err != nil {
				return fmt.Errorf("registering controllers for %s: %w", g.Name, err)
			}
			registered = true
			setStarted(g.Name)
			g.Log.Info("gated controllers started; no longer degraded", "group", g.Name)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}
