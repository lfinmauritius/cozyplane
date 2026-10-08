package vpngateway

import (
	"fmt"
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

func TestVPNGatewayRejectsOversizedPoolCollection(t *testing.T) {
	gw := poolBudgetFixture(129)
	if errs := validateVPNGateway(gw); len(errs) == 0 {
		t.Fatal("129 address pools accepted")
	}
	gw = poolBudgetFixture(128)
	gw.Spec.IPsec.AddressPools[0].DNS = make([]string, 16)
	for i := range gw.Spec.IPsec.AddressPools[0].DNS {
		gw.Spec.IPsec.AddressPools[0].DNS[i] = "10.0.0.53"
	}
	if errs := validateVPNGateway(gw); len(errs) != 0 {
		t.Fatalf("valid exact pool/DNS capacity refused: %v", errs)
	}
}

func TestVPNGatewayRejectsOversizedDNSAndBGPCollections(t *testing.T) {
	gw := poolBudgetFixture(1)
	gw.Spec.IPsec.AddressPools[0].DNS = make([]string, 17)
	for i := range gw.Spec.IPsec.AddressPools[0].DNS {
		gw.Spec.IPsec.AddressPools[0].DNS[i] = "10.0.0.53"
	}
	if errs := validateVPNGateway(gw); len(errs) == 0 {
		t.Fatal("17 pool DNS servers accepted")
	}
	gw = &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "net"}, WireGuard: &sdn.VPNGatewayWireGuard{}, HA: &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeActiveActive, ActiveActive: &sdn.VPNGatewayActiveActive{LocalASN: 64520, PeerASN: 64521, PeerAddresses: make([]string, 65)}}}}
	for i := range gw.Spec.HA.ActiveActive.PeerAddresses {
		gw.Spec.HA.ActiveActive.PeerAddresses[i] = "10.250.0.1"
	}
	if errs := validateVPNGateway(gw); len(errs) == 0 {
		t.Fatal("65 BGP neighbors accepted")
	}
	gw.Spec.HA.ActiveActive.PeerAddresses = gw.Spec.HA.ActiveActive.PeerAddresses[:64]
	if errs := validateVPNGateway(gw); len(errs) != 0 {
		t.Fatalf("valid exact BGP capacity refused: %v", errs)
	}
}

func poolBudgetFixture(n int) *sdn.VPNGateway {
	gw := &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "net"}, IPsec: &sdn.VPNGatewayIPsec{CredentialSecretRef: "gateway-tls"}}}
	for i := range n {
		gw.Spec.IPsec.AddressPools = append(gw.Spec.IPsec.AddressPools, sdn.VPNIPsecAddressPool{Name: fmt.Sprintf("pool-%d", i), CIDR: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)})
	}
	return gw
}

func BenchmarkVPNGatewayPoolValidation(b *testing.B) {
	for _, n := range []int{128, 4096} {
		b.Run(fmt.Sprintf("pools-%d", n), func(b *testing.B) {
			gw := poolBudgetFixture(n)
			b.ReportAllocs()
			for b.Loop() {
				_ = validateVPNGateway(gw)
			}
		})
	}
}
