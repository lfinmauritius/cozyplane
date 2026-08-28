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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VPNGatewayPhase is the lifecycle phase of a VPNGateway.
type VPNGatewayPhase string

const (
	// VPNGatewayPhasePending means the tunnel endpoint is declared but not yet
	// realized (no external address, or the appliance is not up).
	VPNGatewayPhasePending VPNGatewayPhase = "Pending"
	// VPNGatewayPhaseReady means the endpoint has an address and is serving.
	VPNGatewayPhaseReady VPNGatewayPhase = "Ready"
)

// Condition types surfaced in VPNGateway status.
const (
	// VPNGatewayConditionApplianceReady is True when the tunnel-termination
	// appliance is running and holds a Port in the VPC.
	VPNGatewayConditionApplianceReady = "ApplianceReady"
	// VPNGatewayConditionAddressAssigned is True when the tunnel endpoint's
	// FloatingIP has an assigned external address.
	VPNGatewayConditionAddressAssigned = "AddressAssigned"
	// VPNGatewayConditionRoutesProgrammed is True when the VPC route table
	// carries the connections' remote CIDRs toward this gateway.
	VPNGatewayConditionRoutesProgrammed = "RoutesProgrammed"
	// VPNGatewayConditionRemoteCIDRsAccepted is False when a connection declared a
	// remote CIDR overlapping cluster-internal space (pod/service/node/link-local/
	// loopback/multicast). Such a CIDR is refused — it is never added to the
	// forwarding grant or the route table — so a tenant cannot redirect the VPC's
	// own internal traffic into a tunnel (the increment-6 route-CIDR deny-set).
	VPNGatewayConditionRemoteCIDRsAccepted = "RemoteCIDRsAccepted"
)

// VPNGatewayWireGuard configures a WireGuard tunnel endpoint.
type VPNGatewayWireGuard struct {
	// ListenPort is the UDP port the WireGuard endpoint listens on. Zero lets
	// the appliance pick the default.
	// +optional
	ListenPort int32 `json:"listenPort,omitempty"`
}

// VPNGatewayIPsec configures an IPsec (IKEv2) tunnel endpoint terminated by a
// strongSwan appliance (docs/vpn.md §3.2). Its presence selects the IPsec
// backend; the appliance runs charon (route-based, xfrm-interface) rather than
// WireGuard. IKE listens on the fixed UDP 500/4500 — no listen port to pick.
type VPNGatewayIPsec struct {
	// Proposals are the default IKE/ESP proposals for connections that do not set
	// their own (strongSwan proposal syntax, e.g. "aes256-sha256-modp2048").
	// Empty lets charon negotiate its defaults.
	// +optional
	Proposals []string `json:"proposals,omitempty"`
}

// VPNExternalAddress selects the tunnel endpoint's external (public) address —
// the address a remote peer dials. Reused verbatim from the FloatingIP model:
// cozyplane allocates nothing, it consumes what the LB implementation assigns.
type VPNExternalAddress struct {
	// LoadBalancerClass selects which LB implementation allocates and attracts
	// the endpoint address. Empty uses the cluster default.
	// +optional
	LoadBalancerClass string `json:"loadBalancerClass,omitempty"`

	// AddressClaimName names an IPAddressClaim reservation whose address the
	// endpoint should wear. Reserving it matters for IPsec, whose remote peer
	// pins the endpoint address (docs/vpn.md §3.2). Empty means dynamic.
	// +optional
	AddressClaimName string `json:"addressClaimName,omitempty"`
}

// VPNGatewaySpec declares a managed tunnel endpoint for a VPC (issue #6).
type VPNGatewaySpec struct {
	// VPCRef is the VPC this gateway terminates tunnels into, in this namespace.
	VPCRef LocalVPCRef `json:"vpcRef"`

	// WireGuard configures a WireGuard endpoint. Exactly one tunnel backend is
	// set per gateway.
	// +optional
	WireGuard *VPNGatewayWireGuard `json:"wireguard,omitempty"`

	// IPsec configures an IKEv2/strongSwan endpoint — the enterprise-interop
	// backend (issue #6). Exactly one of WireGuard or IPsec is set.
	// +optional
	IPsec *VPNGatewayIPsec `json:"ipsec,omitempty"`

	// ExternalAddress is the public endpoint a remote peer dials.
	// +optional
	ExternalAddress VPNExternalAddress `json:"externalAddress,omitempty"`

	// HighAvailability runs the tunnel appliance as a warm standby pair on
	// distinct nodes (anti-affinity, same identity) instead of a single replica
	// (docs/vpn.md §3.5, tier 2). A node loss then costs one handshake, not a
	// reschedule: the controller's oldest-wins Port resolution re-targets the
	// FloatingIP and the route to the survivor. The crash-zero-drop tier
	// (dual-tunnel + BGP) is a later increment.
	// +optional
	HighAvailability bool `json:"highAvailability,omitempty"`
}

// VPNGatewayStatus is the observed state of a VPNGateway.
type VPNGatewayStatus struct {
	// Address is the assigned external endpoint address — what a tenant reads
	// out to configure the remote peer.
	// +optional
	Address string `json:"address,omitempty"`

	// PublicKey is the WireGuard public key of this gateway's endpoint, which the
	// tenant configures the remote peer with. The private key stays in a Secret
	// the appliance mounts; only the public half is surfaced.
	// +optional
	PublicKey string `json:"publicKey,omitempty"`

	// AppliancePort is the cluster-scoped Port name of the tunnel appliance's
	// leg in the VPC — the next-hop the connections' routes resolve to.
	// +optional
	AppliancePort string `json:"appliancePort,omitempty"`

	// Routes reports the connections' remote CIDRs and the Port they are
	// programmed toward, merged into the VPC route table by the agent (the same
	// shape VPCGateway.status.routes uses).
	// +optional
	Routes []VPCGatewayRouteStatus `json:"routes,omitempty"`

	// Phase is the lifecycle phase.
	// +optional
	Phase VPNGatewayPhase `json:"phase,omitempty"`

	// Conditions is the detailed state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="VPC",type=string,JSONPath=`.spec.vpcRef.name`
// +kubebuilder:printcolumn:name="Address",type=string,JSONPath=`.status.address`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VPNGateway is a managed tunnel endpoint for a VPC (issue #6): the controller
// runs the tunnel-termination appliance, gives it a FloatingIP endpoint, grants
// its Port the scoped forwarding right, and routes the connections' remote
// CIDRs to it. The crypto lives in the appliance's netns; cozyplane provides
// identity, delivery, routing, policy and metering around it (docs/vpn.md §3.2).
type VPNGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VPNGatewaySpec   `json:"spec,omitempty"`
	Status VPNGatewayStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPNGatewayList contains a list of VPNGateway.
type VPNGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPNGateway `json:"items"`
}
