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

package sdn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// VPNGatewayConfig parameterizes the managed tunnel appliances the controller
// runs (issue #6, docs/vpn.md §3.2, §3.5).
type VPNGatewayConfig struct {
	// Image is the cozyplane image (the vpn-gateway binary ships in it). Empty
	// disables VPNGateway reconciliation.
	Image string
	// DefaultListenPort is the WireGuard UDP port used when a VPNGateway does not
	// pin one.
	DefaultListenPort int32

	// Guardrails (increment 6, docs/vpn.md §3.5): keep a heavy tunnel's blast
	// radius bounded to the gateway pool, never the cluster.

	// NodeSelector places appliances on a dedicated gateway node-pool. Empty runs
	// them anywhere.
	NodeSelector map[string]string
	// Tolerations let the appliance schedule onto a tainted gateway pool.
	Tolerations []corev1.Toleration
	// Resources are the appliance's requests/limits. A zero value is defaulted
	// (limits are mandatory — a crypto workload must never be able to starve the
	// node it shares).
	Resources corev1.ResourceRequirements
	// MaxGatewaysPerNamespace caps a tenant's tunnel gateways; zero defaults.
	MaxGatewaysPerNamespace int
	// MaxConnectionsPerGateway caps a gateway's peers; zero defaults.
	MaxConnectionsPerGateway int
	// InternalCIDRs are the cluster-internal networks (pod, service, node) a
	// remote CIDR must not overlap — the route-CIDR deny-set. A tenant declaring
	// one as a tunnel remote could otherwise redirect the VPC's own internal
	// traffic into the tunnel. Loopback/link-local/multicast are always refused
	// on top of these.
	InternalCIDRs []*net.IPNet
}

// reservedCIDRs are always-forbidden remote prefixes, independent of the
// cluster's pod/service/node networks: loopback, link-local, CGNAT, multicast,
// and their IPv6 equivalents. A tunnel that captured these would break or
// hijack host-local and control-plane traffic.
var reservedCIDRs = mustParseCIDRs(
	"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4",
	"::1/128", "fe80::/10", "ff00::/8",
)

func mustParseCIDRs(ss ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(ss))
	for _, s := range ss {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// Guardrail defaults, applied when the config leaves a field zero.
const (
	defaultMaxGatewaysPerNamespace  = 8
	defaultMaxConnectionsPerGateway = 16
)

// applianceResources returns the appliance's resource requirements, defaulting a
// zero config to modest requests and hard limits (the blast-radius bound).
func (r *VPNGatewayReconciler) applianceResources() corev1.ResourceRequirements {
	if len(r.Config.Resources.Limits) > 0 || len(r.Config.Resources.Requests) > 0 {
		return r.Config.Resources
	}
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("50m"),
			corev1.ResourceMemory: resource.MustParse("64Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("256Mi"),
		},
	}
}

func (r *VPNGatewayReconciler) maxGatewaysPerNamespace() int {
	if r.Config.MaxGatewaysPerNamespace > 0 {
		return r.Config.MaxGatewaysPerNamespace
	}
	return defaultMaxGatewaysPerNamespace
}

func (r *VPNGatewayReconciler) maxConnectionsPerGateway() int {
	if r.Config.MaxConnectionsPerGateway > 0 {
		return r.Config.MaxConnectionsPerGateway
	}
	return defaultMaxConnectionsPerGateway
}

// VPNGatewayReconciler realizes a VPNGateway (issue #6): it runs a WireGuard
// tunnel appliance attached to the VPC, grants that appliance a scoped
// forwarding right for the connections' remote CIDRs, gives it a FloatingIP
// endpoint a remote peer dials, and resolves its Port so the agent routes the
// remote CIDRs to it. The crypto lives in the appliance's netns; this controller
// only wires cozyplane's identity, delivery, policy and routing around it.
//
// It composes existing objects rather than reaching into the datapath: a
// VPCBinding (the scoped grant from increment 2), a FloatingIP (bidirectional
// ingress), and status.Routes the agent programs into vpc_routes (increment 1).
type VPNGatewayReconciler struct {
	client.Client
	// Reader is a non-cached client for the quota count — a stale informer read
	// would let a burst of concurrent creates each pass the cap before any lands
	// in cache. Optional; falls back to the cached client.
	Reader client.Reader
	Scheme *runtime.Scheme
	Config VPNGatewayConfig
}

// quotaReader returns the live reader when wired, else the cached client.
func (r *VPNGatewayReconciler) quotaReader() client.Reader {
	if r.Reader != nil {
		return r.Reader
	}
	return r.Client
}

// Labels/annotations on a VPNGateway's owned objects.
const (
	// vpnGatewayLabel links an owned object (Deployment, Secret, VPCBinding,
	// FloatingIP) back to its VPNGateway.
	vpnGatewayLabel = "sdn.cozystack.io/vpn-gateway"
	// vpnConfigChecksumAnnotation rolls the appliance when its peer set changes.
	vpnConfigChecksumAnnotation = "sdn.cozystack.io/vpn-config-checksum"
)

// tunnel backends. Exactly one is set on a gateway.
const (
	backendWireGuard = "wireguard"
	backendIPsec     = "ipsec"
)

// backendOf reports which tunnel backend a gateway declares (WireGuard default
// when neither is set, so an under-specified gateway still renders something
// coherent rather than wedging).
func backendOf(gw *sdnv1alpha1.VPNGateway) string {
	if gw.Spec.IPsec != nil {
		return backendIPsec
	}
	return backendWireGuard
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpngateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpngateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpnconnections,verbs=get;list;watch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpnconnections/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcbindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=floatingips,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=ports,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// Reconcile realizes the gateway's appliance, grant, endpoint and routes.
func (r *VPNGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	gw := &sdnv1alpha1.VPNGateway{}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if r.Config.Image == "" {
		return ctrl.Result{}, nil
	}

	vpc := &sdnv1alpha1.VPC{}
	vpcOK := false
	if name := gw.Spec.VPCRef.Name; name != "" {
		err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: name}, vpc)
		vpcOK = err == nil
		if err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("fetch VPC: %w", err)
		}
	}
	if !vpcOK {
		return r.reportUnready(ctx, gw, "VPCUnresolved",
			fmt.Sprintf("spec.vpcRef %q names no VPC in this namespace", gw.Spec.VPCRef.Name))
	}

	// The connections this gateway terminates, and the remote prefixes they reach.
	conns, err := r.connectionsFor(ctx, gw)
	if err != nil {
		return ctrl.Result{}, err
	}
	// Route-CIDR deny-set: strip cluster-internal / reserved remote CIDRs before
	// anything consumes them, so a tenant cannot redirect the VPC's own internal
	// traffic into a tunnel. The rejected prefixes surface in a condition.
	rejectedCIDRs := r.filterForbiddenCIDRs(conns)
	fwdCIDRs := unionRemoteCIDRs(conns)
	backend := backendOf(gw)

	// Per-tenant quota (increment 6): reject a gateway beyond the namespace cap or
	// a gateway with too many peers, before materializing anything — a tenant must
	// not be able to stand up unbounded crypto workloads. Under-quota gateways are
	// untouched; the offender is held Pending with a QuotaExceeded reason.
	if reason, err := r.overQuota(ctx, gw, conns); err != nil {
		return ctrl.Result{}, err
	} else if reason != "" {
		// An over-quota gateway must realize NOTHING — tear down anything a race
		// on the informer cache let a concurrent reconcile create, so the
		// forwarding grant, tunnel and public IP are actually revoked rather than
		// left running behind a cosmetic Pending status.
		if err := r.teardownOwned(ctx, gw); err != nil {
			return ctrl.Result{}, err
		}
		return r.reportUnready(ctx, gw, "QuotaExceeded", reason)
	}

	// The gateway's WireGuard identity: generated once, kept in a Secret; only the
	// public half is surfaced in status for the tenant to configure the peer.
	// IPsec authenticates by PSK — no keypair, no public key to surface.
	var priv, pub string
	if backend == backendWireGuard {
		priv, pub, err = r.ensureKeypair(ctx, gw)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	// The peer set the appliance mounts. It carries secrets (WG private key / PSKs),
	// so it is a Secret; its checksum rolls the appliance when peers change.
	cfgJSON, err := r.buildConfig(ctx, gw, backend, priv, conns)
	if err != nil {
		return ctrl.Result{}, err
	}
	checksum, err := r.ensureConfigSecret(ctx, gw, cfgJSON)
	if err != nil {
		return ctrl.Result{}, err
	}

	// The scoped forwarding grant (increment 2): the appliance may source the
	// remote CIDRs and nothing else. An empty union means no Ready connection yet
	// — the binding still exists (attach authorization) but grants no forwarding.
	if err := r.ensureBinding(ctx, gw, fwdCIDRs); err != nil {
		return ctrl.Result{}, err
	}

	// The appliance itself.
	if err := r.ensureDeployment(ctx, gw, backend, checksum); err != nil {
		return ctrl.Result{}, err
	}

	// Resolve the appliance's Port (oldest-wins, the total order EffectiveGateway
	// uses) — its IP targets the FloatingIP, its name is the route next-hop.
	appliancePort, applianceIP := r.resolveAppliancePort(ctx, gw, vpc)

	// The endpoint a remote peer dials: a FloatingIP bound 1:1 to the appliance.
	address := ""
	if applianceIP != "" {
		address, err = r.ensureFloatingIP(ctx, gw, applianceIP)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	// The routes the agent programs into vpc_routes: each connection's remote
	// CIDRs toward the appliance Port. Empty until the Port resolves.
	var routes []sdnv1alpha1.VPCGatewayRouteStatus
	if appliancePort != "" {
		for i := range conns {
			c := &conns[i]
			if len(c.Spec.RemoteCIDRs) == 0 {
				continue
			}
			routes = append(routes, sdnv1alpha1.VPCGatewayRouteStatus{
				CIDRs: append([]string(nil), c.Spec.RemoteCIDRs...),
				Port:  appliancePort,
			})
		}
	}

	status := sdnv1alpha1.VPNGatewayStatus{
		Address:       address,
		PublicKey:     pub,
		AppliancePort: appliancePort,
		Routes:        routes,
		Phase:         sdnv1alpha1.VPNGatewayPhasePending,
	}
	setVPNGWCondition(&status, sdnv1alpha1.VPNGatewayConditionApplianceReady, appliancePort != "",
		"ApplianceReady", applianceReadyMessage(appliancePort))
	setVPNGWCondition(&status, sdnv1alpha1.VPNGatewayConditionAddressAssigned, address != "",
		"AddressAssigned", addressMessage(address))
	routesReady := appliancePort != "" && len(routes) == len(nonEmptyRouteConns(conns))
	setVPNGWCondition(&status, sdnv1alpha1.VPNGatewayConditionRoutesProgrammed, routesReady,
		"RoutesProgrammed", routesMessage(routesReady, len(routes)))
	setVPNGWCondition(&status, sdnv1alpha1.VPNGatewayConditionRemoteCIDRsAccepted, len(rejectedCIDRs) == 0,
		remoteCIDRsReason(rejectedCIDRs), remoteCIDRsMessage(rejectedCIDRs))
	if appliancePort != "" && address != "" {
		status.Phase = sdnv1alpha1.VPNGatewayPhaseReady
	}

	if err := r.writeStatus(ctx, gw, status); err != nil {
		return ctrl.Result{}, err
	}
	// The connections' own status (Established/RoutesProgrammed) follows the
	// gateway's readiness — a coarse but honest reflection until the appliance's
	// kernel handshake state is read back (a later increment).
	if err := r.reflectConnectionStatus(ctx, conns, routesReady); err != nil {
		return ctrl.Result{}, err
	}
	logger.Info("VPNGateway reconciled", "vpngateway", req.NamespacedName.String(), "phase", status.Phase)
	return ctrl.Result{}, nil
}

// teardownOwned deletes the active resources a gateway owns — the tunnel
// Deployment, the forwarding-grant VPCBinding, and the FloatingIP endpoint — so
// a rejected gateway grants and serves nothing. The keypair/config Secrets are
// left (inert without the Deployment, and keeping the key stable if the gateway
// later comes back within quota). NotFound is success.
func (r *VPNGatewayReconciler) teardownOwned(ctx context.Context, gw *sdnv1alpha1.VPNGateway) error {
	name := gw.Name + "-vpn"
	objs := []client.Object{
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gw.Namespace}},
		&sdnv1alpha1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gw.Namespace}},
		&sdnv1alpha1.FloatingIP{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gw.Namespace}},
	}
	for _, o := range objs {
		if err := r.Delete(ctx, o); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("teardown %T %q: %w", o, name, err)
		}
	}
	return nil
}

// reportUnready writes a Pending status carrying a single blocking reason when
// the gateway cannot be realized (no VPC), without touching owned objects.
func (r *VPNGatewayReconciler) reportUnready(ctx context.Context, gw *sdnv1alpha1.VPNGateway, reason, msg string) (ctrl.Result, error) {
	status := sdnv1alpha1.VPNGatewayStatus{Phase: sdnv1alpha1.VPNGatewayPhasePending}
	setVPNGWCondition(&status, sdnv1alpha1.VPNGatewayConditionApplianceReady, false, reason, msg)
	setVPNGWCondition(&status, sdnv1alpha1.VPNGatewayConditionAddressAssigned, false, reason, msg)
	setVPNGWCondition(&status, sdnv1alpha1.VPNGatewayConditionRoutesProgrammed, false, reason, msg)
	return ctrl.Result{}, r.writeStatus(ctx, gw, status)
}

// connectionsFor lists the VPNConnections that name this gateway.
func (r *VPNGatewayReconciler) connectionsFor(ctx context.Context, gw *sdnv1alpha1.VPNGateway) ([]sdnv1alpha1.VPNConnection, error) {
	var list sdnv1alpha1.VPNConnectionList
	if err := r.List(ctx, &list, client.InNamespace(gw.Namespace)); err != nil {
		return nil, fmt.Errorf("list VPNConnections: %w", err)
	}
	var out []sdnv1alpha1.VPNConnection
	for i := range list.Items {
		if list.Items[i].Spec.GatewayRef.Name == gw.Name && list.Items[i].DeletionTimestamp.IsZero() {
			out = append(out, list.Items[i])
		}
	}
	// Deterministic order so the config checksum and route status are stable.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// overQuota reports why this gateway exceeds a per-tenant guardrail, or "" when
// within limits. A namespace admits its N oldest gateways (oldest-wins, name
// breaking ties — the same total order everything else uses, so the verdict is
// stable); a gateway admits at most M peers.
func (r *VPNGatewayReconciler) overQuota(ctx context.Context, gw *sdnv1alpha1.VPNGateway,
	conns []sdnv1alpha1.VPNConnection) (string, error) {
	if maxConns := r.maxConnectionsPerGateway(); len(conns) > maxConns {
		return fmt.Sprintf("gateway has %d connections, over the per-gateway limit of %d", len(conns), maxConns), nil
	}
	maxGW := r.maxGatewaysPerNamespace()
	var list sdnv1alpha1.VPNGatewayList
	if err := r.quotaReader().List(ctx, &list, client.InNamespace(gw.Namespace)); err != nil {
		return "", fmt.Errorf("list VPNGateways for quota: %w", err)
	}
	items := make([]*sdnv1alpha1.VPNGateway, 0, len(list.Items))
	for i := range list.Items {
		if list.Items[i].DeletionTimestamp.IsZero() {
			items = append(items, &list.Items[i])
		}
	}
	if len(items) <= maxGW {
		return "", nil
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].CreationTimestamp.Equal(&items[j].CreationTimestamp) {
			return items[i].CreationTimestamp.Before(&items[j].CreationTimestamp)
		}
		return items[i].Name < items[j].Name
	})
	rank := 0
	for i, g := range items {
		if g.Name == gw.Name {
			rank = i
			break
		}
	}
	if rank >= maxGW {
		return fmt.Sprintf("namespace has %d VPN gateways, over the limit of %d (this one is #%d oldest)",
			len(items), maxGW, rank+1), nil
	}
	return "", nil
}

// filterForbiddenCIDRs strips every cluster-internal / reserved remote CIDR from
// the connections in place (the route-CIDR deny-set), so a forbidden prefix
// never reaches the forwarding grant, the route table, or the tunnel peer
// config. It returns the rejected prefixes (with a reason) for the status
// condition. conns is a local copy — reassigning each RemoteCIDRs to a fresh
// slice never touches the informer cache.
func (r *VPNGatewayReconciler) filterForbiddenCIDRs(conns []sdnv1alpha1.VPNConnection) []string {
	var rejected []string
	for i := range conns {
		allowed := make([]string, 0, len(conns[i].Spec.RemoteCIDRs))
		for _, c := range conns[i].Spec.RemoteCIDRs {
			if reason := r.forbiddenRemoteCIDR(c); reason != "" {
				rejected = append(rejected, fmt.Sprintf("%s (%s)", c, reason))
				continue
			}
			allowed = append(allowed, c)
		}
		conns[i].Spec.RemoteCIDRs = allowed
	}
	return rejected
}

// forbiddenRemoteCIDR returns why a remote CIDR is refused, or "" when allowed.
func (r *VPNGatewayReconciler) forbiddenRemoteCIDR(cidr string) string {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return "not a CIDR"
	}
	for _, f := range reservedCIDRs {
		if cidrsOverlap(n, f) {
			return "reserved"
		}
	}
	for _, f := range r.Config.InternalCIDRs {
		if cidrsOverlap(n, f) {
			return "cluster-internal"
		}
	}
	return ""
}

// cidrsOverlap reports whether two prefixes intersect (either contains the
// other's network address) — conservative for the large internal ranges the
// deny-set guards.
func cidrsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// unionRemoteCIDRs collects every connection's remote CIDRs, de-duplicated and
// sorted — the scoped forwarding allowlist.
func unionRemoteCIDRs(conns []sdnv1alpha1.VPNConnection) []string {
	seen := map[string]bool{}
	for i := range conns {
		for _, c := range conns[i].Spec.RemoteCIDRs {
			seen[c] = true
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func nonEmptyRouteConns(conns []sdnv1alpha1.VPNConnection) []sdnv1alpha1.VPNConnection {
	var out []sdnv1alpha1.VPNConnection
	for i := range conns {
		if len(conns[i].Spec.RemoteCIDRs) > 0 {
			out = append(out, conns[i])
		}
	}
	return out
}

// ensureKeypair returns the gateway's WireGuard private/public keys, generating
// and persisting them in an owned Secret on first sight. The private key never
// leaves the Secret; only the public key is returned for status.
func (r *VPNGatewayReconciler) ensureKeypair(ctx context.Context, gw *sdnv1alpha1.VPNGateway) (priv, pub string, err error) {
	name := gw.Name + "-wg-keys"
	sec := &corev1.Secret{}
	getErr := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: name}, sec)
	switch {
	case getErr == nil:
		priv = string(sec.Data["privateKey"])
		pub = string(sec.Data["publicKey"])
		if priv != "" && pub != "" {
			return priv, pub, nil
		}
		// A half-written Secret: regenerate below by falling through to create.
	case !apierrors.IsNotFound(getErr):
		return "", "", fmt.Errorf("get keypair secret: %w", getErr)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("generate wireguard key: %w", err)
	}
	priv, pub = key.String(), key.PublicKey().String()
	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: gw.Namespace,
			Labels:    map[string]string{vpnGatewayLabel: gw.Name},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"privateKey": []byte(priv), "publicKey": []byte(pub)},
	}
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return "", "", err
	}
	if getErr == nil { // half-written: update in place
		sec.Data = desired.Data
		if err := r.Update(ctx, sec); err != nil {
			return "", "", fmt.Errorf("repair keypair secret: %w", err)
		}
		return priv, pub, nil
	}
	if err := r.Create(ctx, desired); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return "", "", nil // lost a race; requeue picks up the winner's keys
		}
		return "", "", fmt.Errorf("create keypair secret: %w", err)
	}
	return priv, pub, nil
}

// buildConfig renders the appliance's tunnel config JSON, dispatching on the
// gateway's backend. Its bytes go into a Secret the appliance mounts.
func (r *VPNGatewayReconciler) buildConfig(ctx context.Context, gw *sdnv1alpha1.VPNGateway,
	backend, priv string, conns []sdnv1alpha1.VPNConnection) ([]byte, error) {
	if backend == backendIPsec {
		return r.buildIPsecConfig(ctx, gw, conns)
	}
	return r.buildWGConfig(ctx, gw, priv, conns)
}

// buildWGConfig renders the WireGuard appliance config — the private key, the
// listen port, and one peer per connection (reading each connection's optional
// preshared-key Secret).
func (r *VPNGatewayReconciler) buildWGConfig(ctx context.Context, gw *sdnv1alpha1.VPNGateway,
	priv string, conns []sdnv1alpha1.VPNConnection) ([]byte, error) {
	type peer struct {
		Name         string   `json:"name,omitempty"`
		PublicKey    string   `json:"publicKey"`
		Endpoint     string   `json:"endpoint,omitempty"`
		AllowedIPs   []string `json:"allowedIPs"`
		PresharedKey string   `json:"presharedKey,omitempty"`
		Keepalive    int      `json:"keepalive,omitempty"`
	}
	cfg := struct {
		PrivateKey string `json:"privateKey"`
		ListenPort int    `json:"listenPort,omitempty"`
		Peers      []peer `json:"peers"`
	}{
		PrivateKey: priv,
		ListenPort: int(r.listenPort(gw)),
	}
	for i := range conns {
		c := &conns[i]
		if c.Spec.WireGuard == nil {
			continue
		}
		p := peer{
			Name:       c.Name,
			PublicKey:  c.Spec.WireGuard.PeerPublicKey,
			Endpoint:   c.Spec.WireGuard.PeerEndpoint,
			AllowedIPs: append([]string(nil), c.Spec.RemoteCIDRs...),
			Keepalive:  int(c.Spec.WireGuard.PersistentKeepalive),
		}
		if ref := c.Spec.WireGuard.PresharedKeySecretRef; ref != "" {
			psk, err := r.readPSK(ctx, gw.Namespace, ref)
			if err != nil {
				return nil, err
			}
			p.PresharedKey = psk
		}
		cfg.Peers = append(cfg.Peers, p)
	}
	return json.Marshal(cfg)
}

// buildIPsecConfig renders the strongSwan appliance config — one peer per IPsec
// connection, each with its PSK (read from the referenced Secret), remote CIDRs,
// proposals (connection override or gateway default), and a stable xfrm if_id
// derived from the connection name so the route-based tunnel binds to its own
// interface.
func (r *VPNGatewayReconciler) buildIPsecConfig(ctx context.Context, gw *sdnv1alpha1.VPNGateway,
	conns []sdnv1alpha1.VPNConnection) ([]byte, error) {
	type peer struct {
		Name        string   `json:"name"`
		PeerAddress string   `json:"peerAddress,omitempty"`
		PSK         string   `json:"psk,omitempty"`
		RemoteCIDRs []string `json:"remoteCIDRs"`
		Proposals   []string `json:"proposals,omitempty"`
		DPDDelay    int      `json:"dpdDelay,omitempty"`
		IfID        uint32   `json:"ifId"`
	}
	var defProposals []string
	if gw.Spec.IPsec != nil {
		defProposals = gw.Spec.IPsec.Proposals
	}
	cfg := struct {
		Peers []peer `json:"peers"`
	}{}
	for i := range conns {
		c := &conns[i]
		if c.Spec.IPsec == nil {
			continue
		}
		proposals := c.Spec.IPsec.Proposals
		if len(proposals) == 0 {
			proposals = defProposals
		}
		p := peer{
			Name:        c.Name,
			PeerAddress: c.Spec.IPsec.PeerAddress,
			RemoteCIDRs: append([]string(nil), c.Spec.RemoteCIDRs...),
			Proposals:   proposals,
			DPDDelay:    int(c.Spec.IPsec.DPDDelay),
			IfID:        ipsecIfID(c.Name),
		}
		if ref := c.Spec.IPsec.Auth.PSKSecretRef; ref != "" {
			psk, err := r.readPSK(ctx, gw.Namespace, ref)
			if err != nil {
				return nil, err
			}
			p.PSK = psk
		}
		cfg.Peers = append(cfg.Peers, p)
	}
	return json.Marshal(cfg)
}

// ipsecIfID maps a connection name to a stable, non-zero 32-bit xfrm if_id (the
// SA ⇄ xfrm-interface binding). A hash keeps it stable across reconciles; a
// handful of peers makes a collision negligible.
func ipsecIfID(name string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	id := h.Sum32()
	if id == 0 {
		id = 1
	}
	return id
}

// readPSK reads a preshared key from a Secret in the gateway's namespace. The
// key is taken from the conventional "psk" or "presharedKey" data key, or the
// Secret's sole entry when it has exactly one.
func (r *VPNGatewayReconciler) readPSK(ctx context.Context, ns, name string) (string, error) {
	sec := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, sec); err != nil {
		if apierrors.IsNotFound(err) {
			return "", nil // not yet present; the tunnel comes up without it until then
		}
		return "", fmt.Errorf("read preshared-key secret %q: %w", name, err)
	}
	for _, k := range []string{"psk", "presharedKey"} {
		if v, ok := sec.Data[k]; ok {
			return string(v), nil
		}
	}
	if len(sec.Data) == 1 {
		for _, v := range sec.Data {
			return string(v), nil
		}
	}
	return "", nil
}

func (r *VPNGatewayReconciler) listenPort(gw *sdnv1alpha1.VPNGateway) int32 {
	if gw.Spec.WireGuard != nil && gw.Spec.WireGuard.ListenPort > 0 {
		return gw.Spec.WireGuard.ListenPort
	}
	if r.Config.DefaultListenPort > 0 {
		return r.Config.DefaultListenPort
	}
	return 51820
}

// ensureConfigSecret writes the tunnel config Secret and returns its content
// checksum (which the appliance pod template carries so a peer change rolls it).
func (r *VPNGatewayReconciler) ensureConfigSecret(ctx context.Context, gw *sdnv1alpha1.VPNGateway, cfgJSON []byte) (string, error) {
	sum := sha256.Sum256(cfgJSON)
	checksum := hex.EncodeToString(sum[:])
	name := gw.Name + "-wg-config"
	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: gw.Namespace,
			Labels:    map[string]string{vpnGatewayLabel: gw.Name},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"config.json": cfgJSON},
	}
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return "", err
	}
	existing := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := r.Create(ctx, desired); err != nil {
			return "", fmt.Errorf("create config secret: %w", err)
		}
	case err != nil:
		return "", fmt.Errorf("get config secret: %w", err)
	default:
		if !equality.Semantic.DeepEqual(existing.Data, desired.Data) {
			existing.Data = desired.Data
			if err := r.Update(ctx, existing); err != nil {
				return "", fmt.Errorf("update config secret: %w", err)
			}
		}
	}
	return checksum, nil
}

// ensureBinding reconciles the VPCBinding that authorizes the appliance to
// attach to the VPC and grants its scoped forwarding right (the union of the
// connections' remote CIDRs). Same namespace as the gateway; the controller
// holds the authority a tenant would not.
func (r *VPNGatewayReconciler) ensureBinding(ctx context.Context, gw *sdnv1alpha1.VPNGateway, fwdCIDRs []string) error {
	name := gw.Name + "-vpn"
	desired := &sdnv1alpha1.VPCBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: gw.Namespace,
			Labels:    map[string]string{vpnGatewayLabel: gw.Name},
		},
		Spec: sdnv1alpha1.VPCBindingSpec{
			VPCRef:          sdnv1alpha1.VPCRef{Namespace: gw.Namespace, Name: gw.Spec.VPCRef.Name},
			AllowForwarding: len(fwdCIDRs) > 0,
			ForwardingCIDRs: fwdCIDRs,
		},
	}
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return err
	}
	existing := &sdnv1alpha1.VPCBinding{}
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("create VPCBinding: %w", err)
		}
	case err != nil:
		return fmt.Errorf("get VPCBinding: %w", err)
	default:
		if !equality.Semantic.DeepEqual(existing.Spec, desired.Spec) {
			existing.Spec = desired.Spec
			if err := r.Update(ctx, existing); err != nil {
				return fmt.Errorf("update VPCBinding: %w", err)
			}
		}
	}
	return nil
}

// ensureDeployment reconciles the tunnel appliance — a VPC-attached pod running
// cozyplane-vpn-gateway, mounting the config Secret. Recreate strategy: it
// claims a Port in the VPC and a rolling replacement would race it.
func (r *VPNGatewayReconciler) ensureDeployment(ctx context.Context, gw *sdnv1alpha1.VPNGateway, backend, checksum string) error {
	desired := r.deployment(gw, backend, checksum)
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return err
	}
	existing := &appsv1.Deployment{}
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("create appliance deployment: %w", err)
		}
	case err != nil:
		return fmt.Errorf("get appliance deployment: %w", err)
	default:
		if !equality.Semantic.DeepDerivative(desired.Spec.Template.Spec.Containers, existing.Spec.Template.Spec.Containers) ||
			!equality.Semantic.DeepDerivative(desired.Spec.Template.Annotations, existing.Spec.Template.Annotations) ||
			!equality.Semantic.DeepEqual(desired.Spec.Replicas, existing.Spec.Replicas) ||
			!equality.Semantic.DeepEqual(desired.Spec.Template.Spec.Affinity, existing.Spec.Template.Spec.Affinity) ||
			!equality.Semantic.DeepEqual(desired.Spec.Template.Spec.NodeSelector, existing.Spec.Template.Spec.NodeSelector) {
			existing.Spec = desired.Spec
			if err := r.Update(ctx, existing); err != nil {
				return fmt.Errorf("update appliance deployment: %w", err)
			}
		}
	}
	return nil
}

func (r *VPNGatewayReconciler) deployment(gw *sdnv1alpha1.VPNGateway, backend, checksum string) *appsv1.Deployment {
	labels := map[string]string{
		"app":           "cozyplane-vpn-gateway",
		vpnGatewayLabel: gw.Name,
	}
	command := "/usr/local/bin/cozyplane-vpn-gateway"
	if backend == backendIPsec {
		command = "/usr/local/bin/cozyplane-vpn-gateway-ipsec"
	}

	// HA warm standby (increment 6, docs/vpn.md §3.5 tier 2): two same-identity
	// replicas anti-affined across nodes. The two share the config Secret (same
	// WG key / IPsec PSK), so either can serve the FloatingIP; the controller's
	// oldest-wins resolution re-targets it to the survivor on a node loss.
	// Per-connection metrics: the WireGuard shim serves them on :9410 for
	// Prometheus/VictoriaMetrics to scrape (docs/vpn.md §6). IPsec metrics (from
	// charon SA counters) are a later increment, so the port/annotations are
	// WireGuard-only for now.
	podAnnotations := map[string]string{
		sdnv1alpha1.AnnotationVPC:   gw.Spec.VPCRef.Name,
		vpnConfigChecksumAnnotation: checksum,
	}
	var ports []corev1.ContainerPort
	if backend == backendWireGuard {
		ports = []corev1.ContainerPort{{Name: "vpn-metrics", ContainerPort: 9410, Protocol: corev1.ProtocolTCP}}
		podAnnotations["prometheus.io/scrape"] = "true"
		podAnnotations["prometheus.io/port"] = "9410"
		podAnnotations["prometheus.io/path"] = "/metrics"
	}

	replicas := int32(1)
	var affinity *corev1.Affinity
	if gw.Spec.HighAvailability {
		replicas = 2
		affinity = &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
				Weight: 100,
				PodAffinityTerm: corev1.PodAffinityTerm{
					LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{vpnGatewayLabel: gw.Name}},
					TopologyKey:   "kubernetes.io/hostname",
				},
			}},
		}}
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      gw.Name + "-vpn",
			Namespace: gw.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(replicas),
			// RollingUpdate keeps a replica up across a config roll (each pod owns
			// a distinct VPC Port, so replacements never race on an identity).
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: ptrIntStr(0),
					MaxSurge:       ptrIntStr(1),
				},
			},
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					// AnnotationVPC attaches the appliance to the VPC as an ordinary
					// member — it gets a Port, and the route table (not the .1 door)
					// steers the remote CIDRs to it. Scrape annotations (WG) sit
					// alongside.
					Annotations: podAnnotations,
				},
				Spec: corev1.PodSpec{
					// Guardrails (increment 6): dedicated gateway node-pool placement
					// and mandatory resource bounds keep a heavy tunnel off the
					// tenant workloads' nodes and its blast radius bounded.
					NodeSelector: r.Config.NodeSelector,
					Tolerations:  r.Config.Tolerations,
					Affinity:     affinity,
					Containers: []corev1.Container{{
						Name:    "vpn-gateway",
						Image:   r.Config.Image,
						Command: []string{command},
						// Privileged: the appliance manages its OWN netns — create a
						// WireGuard/xfrm device, write the forwarding sysctls, and
						// (IPsec) bind IKE's UDP 500/4500. The functional need is only
						// NET_ADMIN + NET_RAW + NET_BIND_SERVICE, but writing
						// net.ipv4.ip_forward needs a writable /proc/sys, which a
						// non-privileged container gets only where the kubelet allows
						// that unsafe sysctl (pod-level securityContext.sysctls). The
						// capability-drop hardening is owed once the platform
						// guarantees that (docs/vpn.md §5); the blast radius is already
						// bounded to the dedicated gateway node-pool (increment 6).
						SecurityContext: &corev1.SecurityContext{Privileged: new(true)},
						Resources:       r.applianceResources(),
						Ports:           ports,
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "config",
							MountPath: "/etc/cozyplane-vpn",
							ReadOnly:  true,
						}},
					}},
					Volumes: []corev1.Volume{{
						Name: "config",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{SecretName: gw.Name + "-wg-config"},
						},
					}},
				},
			},
		},
	}
}

// ptrIntStr returns a pointer to an IntOrString wrapping an int — for the
// rolling-update surge/unavailable knobs.
func ptrIntStr(i int32) *intstr.IntOrString {
	v := intstr.FromInt32(i)
	return &v
}

// resolveAppliancePort finds the appliance's Port in the VPC (oldest-wins, name
// breaking the tie — the same total order the appliance door uses). Returns the
// Port name and its tenant IP, both empty until the CNI has minted the Port.
func (r *VPNGatewayReconciler) resolveAppliancePort(ctx context.Context, gw *sdnv1alpha1.VPNGateway,
	vpc *sdnv1alpha1.VPC) (portName, ip string) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(gw.Namespace),
		client.MatchingLabels{vpnGatewayLabel: gw.Name}); err != nil {
		return "", ""
	}
	live := map[string]bool{}
	for i := range pods.Items {
		if pods.Items[i].DeletionTimestamp == nil {
			live[pods.Items[i].Namespace+"/"+pods.Items[i].Name] = true
		}
	}
	var ports sdnv1alpha1.PortList
	if err := r.List(ctx, &ports, client.MatchingLabels{
		sdnv1alpha1.LabelVPCNamespace: gw.Namespace,
		sdnv1alpha1.LabelVPC:          vpc.Name,
	}); err != nil {
		return "", ""
	}
	var best *sdnv1alpha1.Port
	for i := range ports.Items {
		p := &ports.Items[i]
		if !live[p.Spec.PodNamespace+"/"+p.Spec.PodName] {
			continue
		}
		if best == nil || p.CreationTimestamp.Before(&best.CreationTimestamp) ||
			(p.CreationTimestamp.Equal(&best.CreationTimestamp) && p.Name < best.Name) {
			best = p
		}
	}
	if best == nil {
		return "", ""
	}
	return best.Name, best.Spec.IP
}

// ensureFloatingIP reconciles the tunnel endpoint — a FloatingIP bound 1:1 to
// the appliance's tenant IP, whose external address the remote peer dials.
// Returns the assigned address once the LB implementation fills it.
func (r *VPNGatewayReconciler) ensureFloatingIP(ctx context.Context, gw *sdnv1alpha1.VPNGateway, applianceIP string) (string, error) {
	desired := &sdnv1alpha1.FloatingIP{
		ObjectMeta: metav1.ObjectMeta{
			Name:      gw.Name + "-vpn",
			Namespace: gw.Namespace,
			Labels:    map[string]string{vpnGatewayLabel: gw.Name},
		},
		Spec: sdnv1alpha1.FloatingIPSpec{
			VPCRef:            sdnv1alpha1.LocalVPCRef{Name: gw.Spec.VPCRef.Name},
			Target:            applianceIP,
			LoadBalancerClass: gw.Spec.ExternalAddress.LoadBalancerClass,
			AddressClaimName:  gw.Spec.ExternalAddress.AddressClaimName,
		},
	}
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return "", err
	}
	existing := &sdnv1alpha1.FloatingIP{}
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := r.Create(ctx, desired); err != nil {
			return "", fmt.Errorf("create FloatingIP: %w", err)
		}
		return "", nil // address fills on a later pass
	case err != nil:
		return "", fmt.Errorf("get FloatingIP: %w", err)
	}
	if !equality.Semantic.DeepEqual(existing.Spec, desired.Spec) {
		existing.Spec = desired.Spec
		if err := r.Update(ctx, existing); err != nil {
			return "", fmt.Errorf("update FloatingIP: %w", err)
		}
	}
	return existing.Status.Address, nil
}

// reflectConnectionStatus mirrors the gateway's readiness onto each connection's
// status. It is coarse — true kernel handshake state is read back later — but it
// gives the tenant a per-connection Established/RoutesProgrammed signal now.
func (r *VPNGatewayReconciler) reflectConnectionStatus(ctx context.Context, conns []sdnv1alpha1.VPNConnection, routesReady bool) error {
	for i := range conns {
		c := &conns[i]
		want := sdnv1alpha1.VPNConnectionStatus{Phase: sdnv1alpha1.VPNConnectionPhasePending}
		if routesReady {
			want.Phase = sdnv1alpha1.VPNConnectionPhaseEstablished
		}
		want.Conditions = c.Status.Conditions
		setConnCondition(&want, sdnv1alpha1.VPNConnectionConditionRoutesProgrammed, routesReady,
			"RoutesProgrammed", routesMessage(routesReady, len(c.Spec.RemoteCIDRs)))
		if connStatusEqual(c.Status, want) {
			continue
		}
		for j := range want.Conditions {
			want.Conditions[j].ObservedGeneration = c.Generation
		}
		c.Status = want
		if err := r.Status().Update(ctx, c); err != nil && !apierrors.IsConflict(err) {
			return fmt.Errorf("update VPNConnection status: %w", err)
		}
	}
	return nil
}

func (r *VPNGatewayReconciler) writeStatus(ctx context.Context, gw *sdnv1alpha1.VPNGateway, status sdnv1alpha1.VPNGatewayStatus) error {
	if vpnGWStatusEqual(gw.Status, status) {
		return nil
	}
	for i := range status.Conditions {
		status.Conditions[i].ObservedGeneration = gw.Generation
	}
	gw.Status = status
	if err := r.Status().Update(ctx, gw); err != nil {
		if apierrors.IsConflict(err) {
			return nil
		}
		return fmt.Errorf("update VPNGateway status: %w", err)
	}
	return nil
}

func applianceReadyMessage(port string) string {
	if port != "" {
		return "the tunnel appliance holds Port " + port + " in the VPC"
	}
	return "waiting for the tunnel appliance's Port to appear"
}

func addressMessage(addr string) string {
	if addr != "" {
		return "the endpoint address is " + addr
	}
	return "waiting for the endpoint FloatingIP address"
}

func routesMessage(ready bool, n int) string {
	if ready {
		return fmt.Sprintf("%d remote-CIDR route(s) programmed toward the appliance", n)
	}
	return "remote CIDRs not yet routed toward the appliance"
}

func remoteCIDRsReason(rejected []string) string {
	if len(rejected) == 0 {
		return "RemoteCIDRsAccepted"
	}
	return "ForbiddenRemoteCIDR"
}

func remoteCIDRsMessage(rejected []string) string {
	if len(rejected) == 0 {
		return "every remote CIDR is outside cluster-internal space"
	}
	return "refused remote CIDR(s) overlapping cluster-internal space: " + strings.Join(rejected, ", ")
}

// setVPNGWCondition sets a condition through meta.SetStatusCondition (which fills
// LastTransitionTime and de-duplicates by type).
func setVPNGWCondition(status *sdnv1alpha1.VPNGatewayStatus, condType string, ok bool, reason, msg string) {
	st := metav1.ConditionFalse
	if ok {
		st = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: condType, Status: st, Reason: reason, Message: msg})
}

func setConnCondition(status *sdnv1alpha1.VPNConnectionStatus, condType string, ok bool, reason, msg string) {
	st := metav1.ConditionFalse
	if ok {
		st = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: condType, Status: st, Reason: reason, Message: msg})
}

func vpnGWStatusEqual(a, b sdnv1alpha1.VPNGatewayStatus) bool {
	if a.Phase != b.Phase || a.Address != b.Address || a.PublicKey != b.PublicKey ||
		a.AppliancePort != b.AppliancePort ||
		len(a.Conditions) != len(b.Conditions) ||
		!routeStatusEqual(a.Routes, b.Routes) {
		return false
	}
	for _, ca := range a.Conditions {
		cb := meta.FindStatusCondition(b.Conditions, ca.Type)
		if cb == nil || cb.Status != ca.Status || cb.Reason != ca.Reason || cb.Message != ca.Message {
			return false
		}
	}
	return true
}

func connStatusEqual(a, b sdnv1alpha1.VPNConnectionStatus) bool {
	if a.Phase != b.Phase || len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for _, ca := range a.Conditions {
		cb := meta.FindStatusCondition(b.Conditions, ca.Type)
		if cb == nil || cb.Status != ca.Status || cb.Reason != ca.Reason || cb.Message != ca.Message {
			return false
		}
	}
	return true
}

// SetupWithManager wires the controller: VPNGateway drives it; VPNConnections,
// the appliance's Port and Pod, and owned objects re-enqueue their gateway.
func (r *VPNGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.VPNGateway{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Secret{}).
		Owns(&sdnv1alpha1.VPCBinding{}).
		Owns(&sdnv1alpha1.FloatingIP{}).
		Watches(&sdnv1alpha1.VPNConnection{}, handler.EnqueueRequestsFromMapFunc(r.mapConnectionToGateway)).
		Watches(&sdnv1alpha1.Port{}, handler.EnqueueRequestsFromMapFunc(r.mapPortToVPNGateways)).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.mapPodToVPNGateways)).
		Named("vpngateway").
		Complete(r)
}

func (r *VPNGatewayReconciler) mapConnectionToGateway(ctx context.Context, obj client.Object) []ctrl.Request {
	conn, ok := obj.(*sdnv1alpha1.VPNConnection)
	if !ok || conn.Spec.GatewayRef.Name == "" {
		return nil
	}
	return []ctrl.Request{{NamespacedName: types.NamespacedName{Namespace: conn.Namespace, Name: conn.Spec.GatewayRef.Name}}}
}

// mapPortToVPNGateways re-enqueues the gateways of the Port's VPC namespace when
// an appliance Port appears or moves.
func (r *VPNGatewayReconciler) mapPortToVPNGateways(ctx context.Context, obj client.Object) []ctrl.Request {
	ns := obj.GetLabels()[sdnv1alpha1.LabelVPCNamespace]
	if ns == "" {
		return nil
	}
	return r.vpnGatewaysIn(ctx, ns)
}

// mapPodToVPNGateways re-enqueues the gateway that owns an appliance pod.
func (r *VPNGatewayReconciler) mapPodToVPNGateways(ctx context.Context, obj client.Object) []ctrl.Request {
	name := obj.GetLabels()[vpnGatewayLabel]
	if name == "" {
		return nil
	}
	return []ctrl.Request{{NamespacedName: types.NamespacedName{Namespace: obj.GetNamespace(), Name: name}}}
}

func (r *VPNGatewayReconciler) vpnGatewaysIn(ctx context.Context, namespace string) []ctrl.Request {
	var list sdnv1alpha1.VPNGatewayList
	if err := r.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil
	}
	out := make([]ctrl.Request, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return out
}
