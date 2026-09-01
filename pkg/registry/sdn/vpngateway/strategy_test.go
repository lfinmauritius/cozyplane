package vpngateway

import (
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
)

func TestValidateVPNGatewayAddressPools(t *testing.T) {
	tests := []struct {
		name    string
		gateway *sdn.VPNGateway
		wantErr bool
	}{
		{
			name: "valid roadwarrior pool",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef: sdn.LocalVPCRef{Name: "vpc"},
				IPsec: &sdn.VPNGatewayIPsec{
					CredentialSecretRef: "gateway-ike-tls",
					AddressPools:        []sdn.VPNIPsecAddressPool{{Name: "clients", CIDR: "10.250.0.0/24", DNS: []string{"10.0.0.53"}}},
				},
			}},
		},
		{
			name: "overlapping pools",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef: sdn.LocalVPCRef{Name: "vpc"},
				IPsec: &sdn.VPNGatewayIPsec{
					CredentialSecretRef: "gateway-ike-tls",
					AddressPools: []sdn.VPNIPsecAddressPool{
						{Name: "clients-a", CIDR: "10.250.0.0/24"},
						{Name: "clients-b", CIDR: "10.250.0.128/25"},
					},
				},
			}},
			wantErr: true,
		},
		{
			name: "pool requires TLS credential",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef: sdn.LocalVPCRef{Name: "vpc"},
				IPsec:  &sdn.VPNGatewayIPsec{AddressPools: []sdn.VPNIPsecAddressPool{{Name: "clients", CIDR: "10.250.0.0/24"}}},
			}},
			wantErr: true,
		},
		{
			name: "valid active active",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef: sdn.LocalVPCRef{Name: "vpc"}, WireGuard: &sdn.VPNGatewayWireGuard{},
				HA: &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeActiveActive, ActiveActive: &sdn.VPNGatewayActiveActive{
					LocalASN: 64520, PeerASN: 64521, PeerAddresses: []string{"10.250.0.1"}, BFD: true,
				}},
				ExternalAddress: sdn.VPNExternalAddress{AddressClaimNames: []string{"endpoint-a", "endpoint-b"}},
			}},
		},
		{
			name: "active active needs two distinct claims",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef: sdn.LocalVPCRef{Name: "vpc"}, WireGuard: &sdn.VPNGatewayWireGuard{},
				HA: &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeActiveActive, ActiveActive: &sdn.VPNGatewayActiveActive{
					LocalASN: 64520, PeerASN: 64521, PeerAddresses: []string{"10.250.0.1"},
				}},
				ExternalAddress: sdn.VPNExternalAddress{AddressClaimNames: []string{"endpoint-a"}},
			}},
			wantErr: true,
		},
		{
			name: "valid live migration",
			gateway: &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
				VPCRef: sdn.LocalVPCRef{Name: "vpc"}, IPsec: &sdn.VPNGatewayIPsec{},
				HA: &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeLiveMigration, VirtualMachine: &sdn.VPNGatewayVirtualMachine{
					Image: "registry.invalid/vpn-appliance:test", StateClaimName: "vpn-state",
				}},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(validateVPNGateway(tt.gateway)) > 0; got != tt.wantErr {
				t.Fatalf("errors = %v, wantErr %v", validateVPNGateway(tt.gateway), tt.wantErr)
			}
		})
	}
}
