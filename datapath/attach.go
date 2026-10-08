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

package datapath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

var tcxMu sync.Mutex

// We attach with tcx (BPF links), not classic clsact filters: tcx links are
// independent kernel objects that coexist with other tcx users (notably Cilium,
// whose tc reconciliation strips foreign *classic* tc filters but leaves tcx
// links alone). The links are pinned so they survive the short-lived CNI plugin
// process and agent restarts.

func linkPinPath(ifindex int, ingress bool) string {
	dir := "eg"
	if ingress {
		dir = "in"
	}
	return filepath.Join(PinRoot, "links", fmt.Sprintf("%s-%d", dir, ifindex))
}

// OpenPinnedProgram loads the from-pod (egress) classifier from its bpffs pin.
func OpenPinnedProgram() (*ebpf.Program, error) {
	prog, err := ebpf.LoadPinnedProgram(filepath.Join(PinRoot, progPinName), nil)
	if err != nil {
		return nil, fmt.Errorf("open pinned from_pod program: %w", err)
	}
	return prog, nil
}

// OpenPinnedToPod loads the to-pod (ingress) classifier from its bpffs pin.
func OpenPinnedToPod() (*ebpf.Program, error) {
	prog, err := ebpf.LoadPinnedProgram(filepath.Join(PinRoot, toPodPinName), nil)
	if err != nil {
		return nil, fmt.Errorf("open pinned to_pod program: %w", err)
	}
	return prog, nil
}

// AttachIngress attaches the classifier at the ingress of the given interface
// (a pod's host-side veth) via a pinned tcx link.
func AttachIngress(ifindex int, prog *ebpf.Program) error {
	// Cozyplane must observe pod egress before Cilium. VPC traffic (including
	// cluster-DNS steering) is redirected here and must not be service-translated
	// or policy-processed as a default-network flow first. Default-network traffic
	// returns TCX_NEXT and continues into Cilium normally.
	return attachTCX(ifindex, prog, ebpf.AttachTCXIngress, true, link.Head())
}

// attachIngressFirst attaches a non-pod ingress hook before other tcx users.
// Uplink and overlay processing must precede Cilium because these programs can
// decapsulate or translate the packet before handing it to the host stack.
func attachIngressFirst(ifindex int, prog *ebpf.Program) error {
	return attachTCX(ifindex, prog, ebpf.AttachTCXIngress, true, link.Head())
}

// AttachEgress attaches the to-pod classifier at the egress of a pod's
// host-side veth. Cilium must run first so it observes the inbound packet and
// records connection-tracking state before Cozyplane redirects it to the peer.
func AttachEgress(ifindex int, prog *ebpf.Program) error {
	return attachTCX(ifindex, prog, ebpf.AttachTCXEgress, false, link.Tail())
}

// attachEgressFirst attaches a non-pod egress hook before other tcx users.
// The uplink hook may encapsulate remote-pod traffic, so it must precede
// Cilium's ordinary netdev processing.
func attachEgressFirst(ifindex int, prog *ebpf.Program) error {
	return attachTCX(ifindex, prog, ebpf.AttachTCXEgress, false, link.Head())
}

func attachTCX(ifindex int, prog *ebpf.Program, attach ebpf.AttachType, ingress bool, anchor link.Anchor) error {
	return withBridgeLock(func() error {
		tcxMu.Lock()
		defer tcxMu.Unlock()
		return attachTCXLocked(ifindex, prog, attach, ingress, anchor)
	})
}

func attachTCXLocked(ifindex int, prog *ebpf.Program, attach ebpf.AttachType, ingress bool, anchor link.Anchor) error {
	if err := os.MkdirAll(filepath.Join(PinRoot, "links"), 0o755); err != nil {
		return err
	}
	pin := linkPinPath(ifindex, ingress)
	// Reordering the same program requires detaching it first. Keep a pinned
	// DROP guard through that window, including attach/pin failures and crashes.
	for _, candidate := range []string{pin, pin + "-guard", pin + "-guard-swap"} {
		if _, err := os.Stat(candidate); err == nil {
			if err := installTCXGuard(ifindex, attach, pin+"-guard"); err != nil {
				return err
			}
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := removeTCXPin(pin); err != nil {
		return err
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   prog,
		Attach:    attach,
		Anchor:    anchor,
	})
	if err != nil {
		return fmt.Errorf("attach tcx (ifindex %d): %w", ifindex, err)
	}
	if err := l.Pin(pin); err != nil {
		l.Close()
		return fmt.Errorf("pin tcx link: %w", err)
	}
	// Close our handle; the pin keeps the link (and attachment) alive.
	if err := l.Close(); err != nil {
		return err
	}
	return removeTCXGuard(pin)
}

// One guard per hook survives failed moves without retaining userspace FDs.
// A fresh program ID permits attach-before-swap even when retrying a guard.
func installTCXGuard(ifindex int, attach ebpf.AttachType, pin string) error {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "cp_tcx_guard", Type: ebpf.SchedCLS, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}, // TCX_DROP
	})
	if err != nil {
		return fmt.Errorf("load tcx guard: %w", err)
	}
	defer prog.Close()
	l, err := link.AttachTCX(link.TCXOptions{Interface: ifindex, Program: prog, Attach: attach, Anchor: link.Head()})
	if err != nil {
		return fmt.Errorf("attach tcx guard: %w", err)
	}
	defer l.Close()
	return replaceTCXPin(l, pin)
}

func removeTCXGuard(pin string) error {
	for _, path := range []string{pin + "-guard", pin + "-guard-swap"} {
		if err := removeTCXPin(path); err != nil {
			return fmt.Errorf("remove tcx guard: %w", err)
		}
	}
	return nil
}

// Detach explicitly: dropping a pin alone defers kernel destruction and can
// leave the same program attached long enough to reject its immediate retry.
func removeTCXPin(pin string) error {
	l, err := link.LoadPinnedLink(pin, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer l.Close()
	if err := l.Detach(); err != nil {
		return err
	}
	return l.Unpin()
}

// ReattachIngress swaps an interface's ingress classifier to a new program
// object without requiring a DROP guard: the new
// link is attached before the old pin is replaced, so the interface is never
// without a classifier — a VPC pod must not see an unfiltered window.
func ReattachIngress(ifindex int, prog *ebpf.Program) error {
	return reattachTCX(ifindex, prog, ebpf.AttachTCXIngress, true, link.Head())
}

// ReattachEgress swaps an interface's egress classifier to prog (see
// ReattachIngress).
func ReattachEgress(ifindex int, prog *ebpf.Program) error {
	return reattachTCX(ifindex, prog, ebpf.AttachTCXEgress, false, link.Tail())
}

func podHookNeedsReconcile(own, total int, first bool) bool {
	if own < 0 {
		return true
	}
	if first {
		return own != 0
	}
	return own != total-1
}

func reattachTCX(ifindex int, prog *ebpf.Program, attach ebpf.AttachType, ingress bool, anchor link.Anchor) error {
	return withBridgeLock(func() error {
		return reattachTCXLocked(ifindex, prog, attach, ingress, anchor)
	})
}

func reattachTCXLocked(ifindex int, prog *ebpf.Program, attach ebpf.AttachType, ingress bool, anchor link.Anchor) error {
	tcxMu.Lock()
	defer tcxMu.Unlock()
	if err := os.MkdirAll(filepath.Join(PinRoot, "links"), 0o755); err != nil {
		return err
	}
	// tcx is a program *list*: the new link coexists with the old one (which
	// runs first — its terminal verdicts win until the swap) so ordering is
	// attach-new, then atomically rename the pin over the old link's. Losing
	// its pin drops the old link's last reference and detaches it.
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   prog,
		Attach:    attach,
		Anchor:    anchor,
	})
	if isExist(err) {
		// This exact program is already attached here — a pod ADDed after the
		// agent pinned the fresh programs (the CNI attaches the same pinned
		// object). Already the desired end state.
		return nil
	}
	if err != nil {
		return fmt.Errorf("attach tcx (ifindex %d): %w", ifindex, err)
	}
	if err := replaceTCXPin(l, linkPinPath(ifindex, ingress)); err != nil {
		l.Close()
		return err
	}
	return l.Close()
}

func replaceTCXPin(l link.Link, pin string) error {
	old, err := link.LoadPinnedLink(pin, nil)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if old != nil {
		defer old.Close()
	}
	// bpffs rejects dentry names containing dots (EPERM), so the temp pin uses
	// a dash. Unique per (ifindex, direction), like the pin itself.
	tmp := pin + "-swap"
	_ = os.Remove(tmp)
	if err := l.Pin(tmp); err != nil {
		return fmt.Errorf("pin tcx link: %w", err)
	}
	if err := os.Rename(tmp, pin); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("swap tcx link pin: %w", err)
	}
	if old != nil {
		return old.Detach()
	}
	return nil
}

// ReconcilePodTCXOrder restores the order required by each local pod veth.
// Cozyplane owns VPC traffic and must run first in both directions: its terminal
// verdicts keep Cilium from treating overlapping tenant addresses as fabric
// identities, and DNS replies are rewritten before Cilium can deliver them to
// the hidden fabric address. On the default network Cilium runs first so KPR,
// policy and connection tracking keep their normal semantics. Cilium attaches
// endpoint programs asynchronously after CNI ADD, so CNI-time anchors alone
// cannot guarantee either final order.
func (m *Manager) ReconcilePodTCXOrder() (int, error) {
	veths, err := ListLocalPortVeths()
	if err != nil {
		return 0, err
	}

	type podHook struct {
		name    string
		program *ebpf.Program
		attach  ebpf.AttachType
		ingress bool
		id      ebpf.ProgramID
	}
	hooks := []podHook{
		{name: "from_pod", program: m.objs.CozyplaneFromPod, attach: ebpf.AttachTCXIngress, ingress: true},
		{name: "to_pod", program: m.objs.CozyplaneToPod, attach: ebpf.AttachTCXEgress, ingress: false},
	}
	for i := range hooks {
		info, err := hooks[i].program.Info()
		if err != nil {
			return 0, fmt.Errorf("inspect %s program: %w", hooks[i].name, err)
		}
		programID, ok := info.ID()
		if !ok {
			return 0, fmt.Errorf("%s program has no ID", hooks[i].name)
		}
		hooks[i].id = programID
	}

	moved := 0
	var errs []error
	if _, err := pruneDetachedTCXPins(); err != nil {
		errs = append(errs, err)
	}
	for _, veth := range veths {
		// A non-zero network is a Cozyplane VPC leg. Net zero is the fabric
		// interface shared with Cilium.
		first := veth.Net != 0
		for _, hook := range hooks {
			err := withBridgeLock(func() error {
				tcxMu.Lock()
				defer tcxMu.Unlock()
				// The snapshot may race DEL or ifindex reuse; only mutate the
				// endpoint whose full alias was actually scanned.
				current := cozyVethByIndex(veth.Ifindex)
				if current == nil || current.Attrs().Alias != veth.Alias {
					return nil
				}
				result, err := link.QueryPrograms(link.QueryOptions{Target: veth.Ifindex, Attach: hook.attach})
				if err != nil {
					return fmt.Errorf("query %s tcx hook on ifindex %d: %w", hook.name, veth.Ifindex, err)
				}
				own := -1
				for i, attached := range result.Programs {
					if attached.ID == hook.id {
						own = i
						break
					}
				}
				pin := linkPinPath(veth.Ifindex, hook.ingress)
				if !podHookNeedsReconcile(own, len(result.Programs), first) {
					return removeTCXGuard(pin)
				}
				// Never detach an attached program whose link we do not own.
				if _, err := os.Stat(pin); err != nil && own >= 0 {
					if errors.Is(err, os.ErrNotExist) {
						return nil
					}
					return err
				}
				anchor := link.Tail()
				if first {
					anchor = link.Head()
				}
				if err := attachTCXLocked(veth.Ifindex, hook.program, hook.attach, hook.ingress, anchor); err != nil {
					return fmt.Errorf("reorder %s on ifindex %d: %w", hook.name, veth.Ifindex, err)
				}
				moved++
				return nil
			})
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return moved, errors.Join(errs...)
}

// DetachVeth removes the pinned ingress (from_pod) and egress (to_pod) links for
// an interface (used on CNI DEL). Removing a pin drops the last reference,
// detaching the program.
func DetachVeth(ifindex int) error {
	return withBridgeLock(func() error { return detachVethLocked(ifindex) })
}

func detachVethLocked(ifindex int) error {
	tcxMu.Lock()
	defer tcxMu.Unlock()
	for _, ingress := range []bool{true, false} {
		pin := linkPinPath(ifindex, ingress)
		for _, path := range []string{pin, pin + "-swap", pin + "-guard", pin + "-guard-swap"} {
			if err := removeTCXPin(path); err != nil {
				return err
			}
		}
	}
	return nil
}
