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

// cozyplane-vpn-gateway-ipsec terminates IKEv2/IPsec site-to-site tunnels inside
// a managed appliance pod's own netns (issue #6, docs/vpn.md §3.2), the
// enterprise-interop backend. It runs charon (strongSwan's IKE daemon),
// configures it over VICI from a mounted config (the peers a VPNGateway's
// VPNConnections describe), and terminates each tunnel route-based on an
// xfrm-interface — so decrypted traffic lands on ipsecN and leaves on the VPC
// leg with the remote source (which the appliance's scoped forwarding grant
// admits), exactly as the WireGuard backend does. cozyplane adds no crypto to
// its datapath; charon and the kernel's xfrm stack do it here, in this netns.
//
// Route-based (charon.install_routes=no + per-child if_id) keeps the datapath
// clean: no policy-based IPsec, no netfilter — the SA is selected by the
// xfrm-interface the remote CIDRs route to, not by a kernel SPD match.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/strongswan/govici/vici"
	"github.com/vishvananda/netlink"

	"github.com/lllamnyp/cozyplane/datapath"
)

const (
	viciSocket   = "/var/run/charon.vici"
	charonBinary = "/usr/lib/ipsec/charon"
)

// config is the mounted tunnel description. It carries PSKs, so it is delivered
// as a Secret, never a ConfigMap.
type config struct {
	Peers []peer `json:"peers"`
}

type peer struct {
	Name        string   `json:"name"`
	PeerAddress string   `json:"peerAddress,omitempty"` // remote IKE endpoint; empty = responder-only
	PSK         string   `json:"psk,omitempty"`
	RemoteCIDRs []string `json:"remoteCIDRs"`
	Proposals   []string `json:"proposals,omitempty"`
	DPDDelay    int      `json:"dpdDelay,omitempty"`
	IfID        uint32   `json:"ifId"` // the xfrm if_id binding SA ⇄ ipsec<ifId> interface
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	path := os.Getenv("VPN_CONFIG")
	if path == "" {
		path = "/etc/cozyplane-vpn/config.json"
	}
	if err := run(path, log); err != nil {
		log.Error("vpn-gateway-ipsec failed", "err", err)
		os.Exit(1)
	}
}

func run(path string, log *slog.Logger) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	if err := datapath.WriteProcSys("net/ipv4/ip_forward", "1"); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	_ = datapath.WriteProcSys("net/ipv6/conf/all/forwarding", "1")

	// Preflight the one hard kernel prerequisite before doing anything else, and
	// fail loud rather than bringing IKE up over a tunnel that can carry no
	// traffic. Route-based IPsec needs xfrm-interface support — mainline since
	// Linux 4.19, and the portable choice (it works on any standard kernel that
	// enables it), but NOT compiled into stock Cozystack/Talos as of v1.13.6
	// (kernel 6.18: CONFIG_XFRM_INTERFACE unset). The WireGuard backend needs no
	// such gate; see docs/vpn.md §5.
	if err := probeXfrmSupport(); err != nil {
		return fmt.Errorf("route-based IPsec requires kernel xfrm-interface support (CONFIG_XFRM_INTERFACE), which this node lacks: %w — enable it in the node kernel (mainline since 4.19) or use the WireGuard backend (docs/vpn.md §5)", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// charon runs as our child; if it dies, so must we, so the Deployment
	// restarts the pair. exec.CommandContext only binds the child's lifetime to
	// the context, never the reverse — so charon.Wait() is watched explicitly: a
	// charon that crashes/OOMs on its own resolves the run with an error (a
	// non-zero exit the kubelet restarts), instead of leaving a live pod with a
	// dead tunnel silently black-holing traffic.
	charon := exec.CommandContext(ctx, charonBinary)
	charon.Stdout, charon.Stderr = os.Stderr, os.Stderr
	if err := charon.Start(); err != nil {
		return fmt.Errorf("start charon: %w", err)
	}
	log.Info("charon started", "pid", charon.Process.Pid)
	charonDied := make(chan error, 1)
	go func() { charonDied <- charon.Wait() }()

	sess, err := waitForVICI(ctx, log)
	if err != nil {
		return err
	}
	defer sess.Close()

	for _, p := range cfg.Peers {
		// The xfrm-interface the decrypted traffic lands on. Fatal on failure:
		// support was preflighted above, so a per-peer failure here is a real
		// error (a bad if_id/CIDR), not the kernel-capability gate.
		if err := ensureXfrm(p.IfID, p.RemoteCIDRs); err != nil {
			return fmt.Errorf("peer %q xfrm interface: %w", p.Name, err)
		}
		if err := loadPeer(sess, p); err != nil {
			return fmt.Errorf("load peer %q: %w", p.Name, err)
		}
		log.Info("ipsec connection loaded", "peer", p.Name, "ifId", p.IfID,
			"remoteCIDRs", p.RemoteCIDRs, "peerAddress", p.PeerAddress)
		// Initiate from our side when we know the peer's address; a responder-only
		// peer (no address) waits for the remote to dial.
		if p.PeerAddress != "" {
			if err := initiate(sess, p.Name); err != nil {
				log.Warn("initiate failed (will retry via trap/DPD)", "peer", p.Name, "err", err)
			}
		}
	}
	log.Info("ipsec tunnels configured", "peers", len(cfg.Peers))

	select {
	case <-ctx.Done():
		return nil // a signal: shut down gracefully
	case err := <-charonDied:
		// charon exited on its own (crash/OOM/CVE) — fail the process so the
		// kubelet restarts the pair rather than leaving a dead tunnel up.
		return fmt.Errorf("charon exited unexpectedly: %w", err)
	}
}

// probeXfrmSupport reports whether the kernel supports xfrm-interfaces, by
// creating and deleting a throwaway one. A kernel without CONFIG_XFRM_INTERFACE
// rejects LinkAdd with "operation not supported" / "unknown device type".
func probeXfrmSupport() error {
	const probe = "cpxfrmprobe"
	link := &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: probe}, Ifid: 0x0cb1}
	if err := netlink.LinkAdd(link); err != nil {
		return err
	}
	if l, e := netlink.LinkByName(probe); e == nil {
		_ = netlink.LinkDel(l)
	}
	return nil
}

// ensureXfrm creates (idempotently) the xfrm-interface ipsec<ifId> bound to
// if_id, brings it up, and routes each remote CIDR to it. charon installs no
// routes (install_routes=no); these are what steer traffic into the SA.
func ensureXfrm(ifID uint32, remoteCIDRs []string) error {
	name := fmt.Sprintf("ipsec%d", ifID)
	link := &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		Ifid:      ifID,
	}
	if err := netlink.LinkAdd(link); err != nil && !os.IsExist(err) {
		if _, e := netlink.LinkByName(name); e != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
	}
	dev, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find %s: %w", name, err)
	}
	if err := netlink.LinkSetUp(dev); err != nil {
		return fmt.Errorf("set %s up: %w", name, err)
	}
	for _, cidr := range remoteCIDRs {
		dst, err := netlink.ParseIPNet(cidr)
		if err != nil {
			return fmt.Errorf("remote CIDR %q: %w", cidr, err)
		}
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: dev.Attrs().Index, Dst: dst}); err != nil {
			return fmt.Errorf("route %s dev %s: %w", cidr, name, err)
		}
	}
	return nil
}

// waitForVICI blocks until charon's VICI socket accepts a session (charon takes
// a moment to open it after start), or the context is cancelled.
func waitForVICI(ctx context.Context, log *slog.Logger) (*vici.Session, error) {
	for {
		if _, err := os.Stat(viciSocket); err == nil {
			sess, err := vici.NewSession(vici.WithSocketPath(viciSocket))
			if err == nil {
				return sess, nil
			}
			if sess != nil {
				_ = sess.Close() // never leak a half-open session across retries
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("charon VICI socket never became ready: %w", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// viciChild is one CHILD_SA (the tunnel proper), route-based via if_id.
type viciChild struct {
	LocalTS      []string `vici:"local_ts"`
	RemoteTS     []string `vici:"remote_ts"`
	IfIDIn       string   `vici:"if_id_in"`
	IfIDOut      string   `vici:"if_id_out"`
	Mode         string   `vici:"mode"`
	StartAction  string   `vici:"start_action"`
	DPDAction    string   `vici:"dpd_action,omitempty"`
	ESPProposals []string `vici:"esp_proposals,omitempty"`
}

// viciEnd is one end of the IKE_SA's authentication.
type viciEnd struct {
	Auth string `vici:"auth"`
}

// viciConn is a strongSwan connection (swanctl connections.<name>).
type viciConn struct {
	Version     int                  `vici:"version"`
	LocalAddrs  []string             `vici:"local_addrs,omitempty"`
	RemoteAddrs []string             `vici:"remote_addrs,omitempty"`
	Local       viciEnd              `vici:"local"`
	Remote      viciEnd              `vici:"remote"`
	Children    map[string]viciChild `vici:"children"`
	Proposals   []string             `vici:"proposals,omitempty"`
	DPDDelay    string               `vici:"dpd_delay,omitempty"`
}

// loadPeer loads the peer's PSK (load-shared) and connection (load-conn). The
// tunnel is route-based: TS 0.0.0.0/0 on both ends, selection by if_id.
func loadPeer(sess *vici.Session, p peer) error {
	if p.PSK != "" {
		shared := vici.NewMessage()
		if err := shared.Set("type", "IKE"); err != nil {
			return err
		}
		if err := shared.Set("data", p.PSK); err != nil {
			return err
		}
		// Scope the secret to this peer's address when known, else any peer.
		owners := []string{"%any"}
		if p.PeerAddress != "" {
			owners = []string{p.PeerAddress}
		}
		if err := shared.Set("owners", owners); err != nil {
			return err
		}
		if _, err := sess.CommandRequest("load-shared", shared); err != nil {
			return fmt.Errorf("load-shared: %w", err)
		}
	}

	ifID := strconv.FormatUint(uint64(p.IfID), 10)
	startAction := "trap"
	if p.PeerAddress != "" {
		startAction = "start"
	}
	child := viciChild{
		LocalTS:      []string{"0.0.0.0/0", "::/0"},
		RemoteTS:     []string{"0.0.0.0/0", "::/0"},
		IfIDIn:       ifID,
		IfIDOut:      ifID,
		Mode:         "tunnel",
		StartAction:  startAction,
		ESPProposals: p.Proposals,
	}
	if p.DPDDelay > 0 {
		child.DPDAction = "restart"
	}
	conn := viciConn{
		Version:   2, // IKEv2
		Local:     viciEnd{Auth: "psk"},
		Remote:    viciEnd{Auth: "psk"},
		Children:  map[string]viciChild{p.Name: child},
		Proposals: p.Proposals,
	}
	if p.PeerAddress != "" {
		conn.RemoteAddrs = []string{p.PeerAddress}
	}
	if p.DPDDelay > 0 {
		conn.DPDDelay = strconv.Itoa(p.DPDDelay) + "s"
	}

	connMsg, err := vici.MarshalMessage(conn)
	if err != nil {
		return fmt.Errorf("marshal connection: %w", err)
	}
	req := vici.NewMessage()
	if err := req.Set(p.Name, connMsg); err != nil {
		return err
	}
	if _, err := sess.CommandRequest("load-conn", req); err != nil {
		return fmt.Errorf("load-conn: %w", err)
	}
	return nil
}

// initiate asks charon to bring up the connection now (start_action also traps
// it, but an explicit initiate shortens the first-packet latency).
func initiate(sess *vici.Session, name string) error {
	msg := vici.NewMessage()
	if err := msg.Set("child", name); err != nil {
		return err
	}
	if err := msg.Set("timeout", "-1"); err != nil {
		return err
	}
	_, err := sess.CommandRequest("initiate", msg)
	return err
}
