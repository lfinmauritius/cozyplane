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

// VPNConnectionPhase is the lifecycle phase of a VPNConnection.
type VPNConnectionPhase string

const (
	// VPNConnectionPhasePending means the connection is declared but the tunnel
	// is not yet established.
	VPNConnectionPhasePending VPNConnectionPhase = "Pending"
	// VPNConnectionPhaseEstablished means the tunnel has completed a handshake.
	VPNConnectionPhaseEstablished VPNConnectionPhase = "Established"
)

// Condition types surfaced in VPNConnection status.
const (
	// VPNConnectionConditionEstablished is True once the tunnel has handshaked.
	VPNConnectionConditionEstablished = "Established"
	// VPNConnectionConditionRoutesProgrammed is True when the connection's
	// remote CIDRs are routed toward its gateway.
	VPNConnectionConditionRoutesProgrammed = "RoutesProgrammed"
)

// LocalVPNGatewayRef references a VPNGateway in the same namespace.
type LocalVPNGatewayRef struct {
	// Name is the VPNGateway name within the referring object's namespace.
	Name string `json:"name"`
}

// VPNConnectionWireGuard configures a WireGuard peer.
type VPNConnectionWireGuard struct {
	// PeerPublicKey is the remote peer's WireGuard public key.
	PeerPublicKey string `json:"peerPublicKey"`

	// PeerEndpoint is the remote peer's host:port. Optional — a roaming peer may
	// initiate, and WireGuard learns the endpoint from its handshake.
	// +optional
	PeerEndpoint string `json:"peerEndpoint,omitempty"`

	// PresharedKeySecretRef names a Secret in this namespace holding an optional
	// WireGuard preshared key.
	// +optional
	PresharedKeySecretRef string `json:"presharedKeySecretRef,omitempty"`

	// PersistentKeepalive is the keepalive interval in seconds; zero disables it.
	// +optional
	PersistentKeepalive int32 `json:"persistentKeepalive,omitempty"`
}

// VPNConnectionIPsecAuth configures IPsec peer authentication. PSK first; cert
// auth is a later increment.
type VPNConnectionIPsecAuth struct {
	// PSKSecretRef names a Secret in this namespace holding the pre-shared key
	// (conventional data key "psk", or the Secret's sole entry).
	// +optional
	PSKSecretRef string `json:"pskSecretRef,omitempty"`
}

// VPNConnectionIPsec configures an IKEv2 peer, terminated by a strongSwan
// VPNGateway (docs/vpn.md §3.2).
type VPNConnectionIPsec struct {
	// PeerAddress is the remote IKE endpoint (host or IP). Required for the
	// initiator side; a responder-only peer may leave it empty.
	// +optional
	PeerAddress string `json:"peerAddress,omitempty"`

	// Auth is how the peer authenticates.
	Auth VPNConnectionIPsecAuth `json:"auth"`

	// Proposals overrides the gateway's default IKE/ESP proposals for this peer
	// (strongSwan syntax). Empty inherits the gateway default.
	// +optional
	Proposals []string `json:"proposals,omitempty"`

	// DPDDelay is the dead-peer-detection interval in seconds; zero disables it.
	// +optional
	DPDDelay int32 `json:"dpdDelay,omitempty"`
}

// VPNConnectionSpec declares one tunnel to a remote site (issue #6).
type VPNConnectionSpec struct {
	// GatewayRef is the VPNGateway that terminates this connection, in this
	// namespace.
	GatewayRef LocalVPNGatewayRef `json:"gatewayRef"`

	// RemoteCIDRs are the remote networks reachable over this tunnel — routed
	// into the VPC toward the gateway and admitted as the gateway's scoped
	// forwarding sources.
	RemoteCIDRs []string `json:"remoteCIDRs"`

	// WireGuard configures the peer. Exactly one tunnel backend is set, and it
	// must match the gateway's backend.
	// +optional
	WireGuard *VPNConnectionWireGuard `json:"wireguard,omitempty"`

	// IPsec configures an IKEv2 peer. Exactly one of WireGuard or IPsec is set.
	// +optional
	IPsec *VPNConnectionIPsec `json:"ipsec,omitempty"`
}

// VPNConnectionStatus is the observed state of a VPNConnection.
type VPNConnectionStatus struct {
	// Phase is the lifecycle phase.
	// +optional
	Phase VPNConnectionPhase `json:"phase,omitempty"`

	// LastHandshake is when the tunnel last completed a handshake, read back
	// from the appliance's kernel state.
	// +optional
	LastHandshake *metav1.Time `json:"lastHandshake,omitempty"`

	// Conditions is the detailed state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Gateway",type=string,JSONPath=`.spec.gatewayRef.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VPNConnection is one tunnel to a remote site, terminated by a VPNGateway
// (issue #6). Its remote CIDRs become route-table entries toward the gateway
// and the gateway's scoped forwarding allowlist (docs/vpn.md §3.2).
type VPNConnection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VPNConnectionSpec   `json:"spec,omitempty"`
	Status VPNConnectionStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPNConnectionList contains a list of VPNConnection.
type VPNConnectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPNConnection `json:"items"`
}
