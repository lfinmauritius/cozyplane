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
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Two gauges rather than one, because they answer different questions and can
// legitimately disagree: served can drop back to 0 while started stays 1 (the
// apiserver was removed under running controllers), and that combination is
// precisely the state an operator wants to see.
var (
	apiGroupServed = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cozyplane_controller_api_group_served",
		Help: "1 when the gated API group/version answers discovery, 0 when it does not.",
	}, []string{"group"})

	apiGroupControllersStarted = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cozyplane_controller_api_group_controllers_started",
		Help: "1 once the controllers gated on this API group/version have been added to the manager. " +
			"0 means the controller is running degraded.",
	}, []string{"group"})
)

func init() {
	metrics.Registry.MustRegister(apiGroupServed, apiGroupControllersStarted)
}

func setServed(group string, served bool) {
	v := 0.0
	if served {
		v = 1.0
	}
	apiGroupServed.WithLabelValues(group).Set(v)
	// Touch the started gauge so "degraded" is an explicit 0 rather than an
	// absent series that a dashboard cannot distinguish from a dead process.
	apiGroupControllersStarted.WithLabelValues(group).Add(0)
}

func setStarted(group string) {
	apiGroupControllersStarted.WithLabelValues(group).Set(1)
}
