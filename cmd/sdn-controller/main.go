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
	"crypto/tls"
	"flag"
	"net"
	"os"
	"strings"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	localsdnctrl "github.com/lllamnyp/cozyplane/internal/controller/localsdn"
	sdncontroller "github.com/lllamnyp/cozyplane/internal/controller/sdn"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(sdnv1alpha1.AddToScheme(scheme))
	utilruntime.Must(localv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          string
		enableLeaderElection bool
		probeAddr            string
		secureMetrics        bool
		enableHTTP2          bool
		gatewayImage         string
		gatewayNamespace     string
		internalCIDRs        string
		clusterDNS           string
		vpnNodeSelector      string
		vpnTolerationKey     string
		vpnMaxGateways       int
		vpnMaxConnections    int
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics server")
	flag.StringVar(&gatewayImage, "gateway-image", "",
		"cozyplane image for VPC egress gateway pods; empty disables gateway reconciliation")
	flag.StringVar(&gatewayNamespace, "gateway-namespace", os.Getenv("POD_NAMESPACE"),
		"system namespace for gateway Deployments (must match the agents' namespace; defaults to POD_NAMESPACE)")
	flag.StringVar(&internalCIDRs, "internal-cidrs", "",
		"comma-separated cluster-internal CIDRs gateways must not forward tenant traffic to (pod, service, node networks)")
	flag.StringVar(&clusterDNS, "cluster-dns", "",
		"cluster DNS ClusterIP gateways allow on :53")
	flag.StringVar(&vpnNodeSelector, "vpn-gateway-node-selector", "",
		"comma-separated key=value node labels placing managed VPN appliances on a dedicated gateway pool (issue #6, docs/vpn.md §3.5); empty runs them anywhere")
	flag.StringVar(&vpnTolerationKey, "vpn-gateway-toleration-key", "",
		"taint key the managed VPN appliance tolerates (Exists/NoSchedule), so it can schedule onto a tainted gateway pool; empty adds no toleration")
	flag.IntVar(&vpnMaxGateways, "vpn-max-gateways-per-namespace", 0,
		"per-tenant cap on managed VPN gateways (0 uses the built-in default)")
	flag.IntVar(&vpnMaxConnections, "vpn-max-connections-per-gateway", 0,
		"per-gateway cap on VPN connections/peers (0 uses the built-in default)")

	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	var tlsOpts []func(*tls.Config)
	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, func(c *tls.Config) {
			setupLog.Info("disabling http/2")

			c.NextProtos = []string{"http/1.1"}
		})
	}

	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}
	if secureMetrics {
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "sdn-controller.cozystack.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err := (&sdncontroller.VPCReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		// VNI allocation must read live, never the lagging informer cache —
		// a stale read hands two VPCs the same network id (isolation break).
		Reader: mgr.GetAPIReader(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "VPC")
		os.Exit(1)
	}

	if err := (&sdncontroller.VPCBindingReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "VPCBinding")
		os.Exit(1)
	}

	if err := (&sdncontroller.VPCPeeringReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "VPCPeering")
		os.Exit(1)
	}

	if err := (&sdncontroller.PortGCReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		// Claimant-gone checks confirm against the API server directly — a
		// stale cache read must not GC a just-created pod's newborn Port.
		Reader: mgr.GetAPIReader(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PortGC")
		os.Exit(1)
	}

	if err := (&sdncontroller.FloatingIPReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FloatingIP")
		os.Exit(1)
	}

	if err := (&sdncontroller.PersistentPortReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PersistentPort")
		os.Exit(1)
	}

	if err := (&sdncontroller.ServiceVIPReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Reader: mgr.GetAPIReader(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ServiceVIP")
		os.Exit(1)
	}

	if err := (&sdncontroller.SecurityGroupReconciler{
		Client: mgr.GetClient(),
		Reader: mgr.GetAPIReader(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "SecurityGroup")
		os.Exit(1)
	}

	if err := (&sdncontroller.PortMembershipReconciler{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PortMembership")
		os.Exit(1)
	}

	if err := (&sdncontroller.VPCGatewayReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "VPCGateway")
		os.Exit(1)
	}

	if gatewayImage != "" {
		if gatewayNamespace == "" {
			setupLog.Error(nil, "--gateway-namespace (or POD_NAMESPACE) is required with --gateway-image")
			os.Exit(1)
		}
		if err := (&sdncontroller.GatewayReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
			Config: sdncontroller.GatewayConfig{
				Image:         gatewayImage,
				Namespace:     gatewayNamespace,
				InternalCIDRs: internalCIDRs,
				ClusterDNS:    clusterDNS,
			},
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "Gateway")
			os.Exit(1)
		}

		// Managed VPN tunnels (issue #6): the same cozyplane image ships the
		// vpn-gateway binary, so it is gated on the same --gateway-image.
		var vpnTolerations []corev1.Toleration
		if vpnTolerationKey != "" {
			vpnTolerations = []corev1.Toleration{{
				Key:      vpnTolerationKey,
				Operator: corev1.TolerationOpExists,
				Effect:   corev1.TaintEffectNoSchedule,
			}}
		}
		if err := (&sdncontroller.VPNGatewayReconciler{
			Client: mgr.GetClient(),
			// Live reads for the tunnel quota — a stale cache would let a burst of
			// concurrent creates each slip under the cap.
			Reader: mgr.GetAPIReader(),
			Scheme: mgr.GetScheme(),
			Config: sdncontroller.VPNGatewayConfig{
				Image:                    gatewayImage,
				DefaultListenPort:        51820,
				NodeSelector:             parseNodeSelector(vpnNodeSelector),
				Tolerations:              vpnTolerations,
				MaxGatewaysPerNamespace:  vpnMaxGateways,
				MaxConnectionsPerGateway: vpnMaxConnections,
				// The route-CIDR deny-set reuses the same cluster-internal networks
				// the gateway pods are told never to forward to.
				InternalCIDRs: parseCIDRs(internalCIDRs),
			},
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "VPNGateway")
			os.Exit(1)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}

	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting sdn-controller")

	// The local layer's GC: reclaim underlay addresses whose pod is gone
	// (docs/api-groups.md). It reconciles a CRD-served kind, so it works on a
	// cluster with no aggregated apiserver at all.
	if err := (&localsdnctrl.FabricIPReconciler{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "FabricIP")
		os.Exit(1)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// parseNodeSelector turns a "k=v,k2=v2" flag into a label map. Malformed entries
// are skipped rather than fatal — a placement hint should never wedge startup.
func parseNodeSelector(s string) map[string]string {
	if s == "" {
		return nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) == 2 && kv[0] != "" {
			out[kv[0]] = kv[1]
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseCIDRs turns a comma-separated CIDR list into parsed networks, skipping
// malformed entries (a placement/deny-set hint must never wedge startup).
func parseCIDRs(s string) []*net.IPNet {
	if s == "" {
		return nil
	}
	var out []*net.IPNet
	for _, c := range strings.Split(s, ",") {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
			out = append(out, n)
		}
	}
	return out
}
