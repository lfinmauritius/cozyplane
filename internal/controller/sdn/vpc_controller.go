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
	"fmt"
	"strconv"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/ipam"
)

// firstVNI is the lowest network id handed out to VPCs. Ids below it are
// reserved (0 is the default/system network).
const firstVNI int32 = 100

const (
	lastVNI              int32 = 1<<22 - 1 // upper Geneve bits encode forwarding/gateway flags
	vniCounterNamespace        = "kube-system"
	vniCounterName             = "cozyplane-vni-allocator"
	vniCounterAnnotation       = "sdn.cozystack.io/last-vni"
	vniOperationTimeout        = 30 * time.Second
)

// VPCReconciler assigns each VPC a unique network id (VNI) and marks it Ready.
// The datapath (agent) keys isolation and the overlay on this id.
//
// VPC CIDRs may overlap freely (isolation is by overlay, not address space):
// everything a tenant addresses is delivered by (net id, IP), so two VPCs can
// share a CIDR — even the cluster pod CIDR — and stay distinct. The one
// restriction is that overlapping VPCs cannot *peer* (peered traffic is routed
// natively), enforced in the peering path, not here.
type VPCReconciler struct {
	client.Client

	Scheme *runtime.Scheme

	// Reader reads VPCs from the API server directly, bypassing the informer
	// cache (mgr.GetAPIReader()). Allocation MUST NOT use the cache: it lags the
	// reconciler's own status writes, so two back-to-back reconciles of fresh
	// VPCs could both see a VNI as free and assign it twice — two tenants
	// sharing a network id is a cross-tenant isolation break. Reconciles are
	// serial (default MaxConcurrentReconciles), so a live list plus
	// assign-before-return is race-free. Falls back to Client when nil (tests).
	Reader client.Reader
}

// reader returns the live API reader, or the (already live in tests) client.
func (r *VPCReconciler) reader() client.Reader {
	if r.Reader != nil {
		return r.Reader
	}
	return r.Client
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcs,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;create;update

// Reconcile assigns a VNI to the VPC if it has none, then sets phase Ready.
func (r *VPCReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	vpc := &sdnv1alpha1.VPC{}
	if err := r.Get(ctx, req.NamespacedName, vpc); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetch VPC: %w", err)
	}
	if !vpc.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	originalVNI, originalPhase := vpc.Status.VNI, vpc.Status.Phase

	if vpc.Status.VNI == 0 {
		vni, err := r.allocateVNI(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		vpc.Status.VNI = vni
	} else if lost, err := r.lostVNIToDuplicate(ctx, vpc); err != nil {
		return ctrl.Result{}, err
	} else if lost {
		// Duplicate repair (pre-live-list clusters): another VPC holds this VNI
		// and wins the deterministic tiebreak; yield and reallocate. The agents
		// re-key the datapath from the new id at watch latency.
		logger.Info("VPC yields duplicate VNI", "name", vpc.Name, "vni", vpc.Status.VNI)
		vni, err := r.allocateVNI(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		vpc.Status.VNI = vni
	}
	vpc.Status.Phase = sdnv1alpha1.VPCPhaseReady
	if vpc.Status.VNI == originalVNI && vpc.Status.Phase == originalPhase {
		return ctrl.Result{}, nil
	}

	if err := r.Status().Update(ctx, vpc); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update VPC status: %w", err)
	}

	logger.Info("VPC ready", "name", vpc.Name, "vni", vpc.Status.VNI)
	return ctrl.Result{}, nil
}

// allocateVNI durably reserves a never-reused identifier before status exposes
// it. Failed status updates intentionally burn reservations rather than recycle.
func (r *VPCReconciler) allocateVNI(ctx context.Context) (int32, error) {
	ctx, cancel := context.WithTimeout(ctx, vniOperationTimeout)
	defer cancel()
	var allocated int32
	var attemptErr error
	err := retry.OnError(retry.DefaultRetry, func(err error) bool {
		return apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err)
	}, func() (err error) {
		// client-go's retry helper can discard an interrupted attempt's error.
		// Preserve its actual result independently of the helper's return value.
		defer func() { attemptErr = err }()
		if err := ctx.Err(); err != nil {
			return err
		}
		counter := &coordinationv1.Lease{}
		err = r.reader().Get(ctx, client.ObjectKey{Namespace: vniCounterNamespace, Name: vniCounterName}, counter)
		if apierrors.IsNotFound(err) {
			high, err := r.initialVNIHighWater(ctx)
			if err != nil {
				return err
			}
			if high >= lastVNI {
				return fmt.Errorf("VNI range exhausted")
			}
			candidate := high + 1
			counter.ObjectMeta = metav1.ObjectMeta{Namespace: vniCounterNamespace, Name: vniCounterName,
				Annotations: map[string]string{vniCounterAnnotation: strconv.FormatInt(int64(candidate), 10)}}
			if err := r.Create(ctx, counter); err != nil {
				return err
			}
			allocated = candidate
			return nil
		}
		if err != nil {
			return fmt.Errorf("read durable VNI counter: %w", err)
		}
		if !counter.DeletionTimestamp.IsZero() {
			return fmt.Errorf("durable VNI counter is being deleted")
		}
		high, err := strconv.ParseInt(counter.Annotations[vniCounterAnnotation], 10, 32)
		if err != nil || high < int64(firstVNI-1) || high > int64(lastVNI) {
			return fmt.Errorf("durable VNI counter is invalid")
		}
		if high == int64(lastVNI) {
			return fmt.Errorf("VNI range exhausted")
		}
		candidate := int32(high) + 1
		counter.Annotations[vniCounterAnnotation] = strconv.FormatInt(int64(candidate), 10)
		if err := r.Update(ctx, counter); err != nil {
			return err
		}
		allocated = candidate
		return nil
	})
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if attemptErr != nil {
		return 0, attemptErr
	}
	if err != nil {
		return 0, err
	}
	if allocated < firstVNI || allocated > lastVNI {
		return 0, fmt.Errorf("VNI reservation completed without a confirmed counter write")
	}
	return allocated, nil
}

// Bootstrap only: live claims also retain a retired VPC's network identity.
// Existing counters avoid scans proportional to all historical allocations.
func (r *VPCReconciler) initialVNIHighWater(ctx context.Context) (int32, error) {
	ctx, cancel := context.WithTimeout(ctx, vniOperationTimeout)
	defer cancel()
	high := firstVNI - 1
	if err := ipam.WalkClaims(ctx, func(limit int64, token string) ([]sdnv1alpha1.VPC, string, error) {
		var list sdnv1alpha1.VPCList
		err := r.reader().List(ctx, &list, client.Limit(limit), client.Continue(token))
		return list.Items, list.Continue, err
	}, func(vpc *sdnv1alpha1.VPC) {
		high = max(high, vpc.Status.VNI)
	}); err != nil {
		return 0, fmt.Errorf("list VPC VNI claims: %w", err)
	}
	if err := ipam.WalkClaims(ctx, func(limit int64, token string) ([]sdnv1alpha1.Port, string, error) {
		var list sdnv1alpha1.PortList
		err := r.reader().List(ctx, &list, client.Limit(limit), client.Continue(token))
		return list.Items, list.Continue, err
	}, func(port *sdnv1alpha1.Port) {
		if vni, _, ok := sdn.ParseClaim(sdn.ClaimPrefixPort, port.Name); ok {
			high = max(high, vni)
		}
	}); err != nil {
		return 0, fmt.Errorf("list Port VNI claims: %w", err)
	}
	if err := ipam.WalkClaims(ctx, func(limit int64, token string) ([]sdnv1alpha1.ServiceVIP, string, error) {
		var list sdnv1alpha1.ServiceVIPList
		err := r.reader().List(ctx, &list, client.Limit(limit), client.Continue(token))
		return list.Items, list.Continue, err
	}, func(vip *sdnv1alpha1.ServiceVIP) {
		if vni, _, ok := sdn.ParseClaim(sdn.ClaimPrefixServiceVIP, vip.Name); ok {
			high = max(high, vni)
		}
	}); err != nil {
		return 0, fmt.Errorf("list ServiceVIP VNI claims: %w", err)
	}
	return high, nil
}

// lostVNIToDuplicate reports whether vpc shares its VNI with another VPC that
// wins the deterministic tiebreak — older creationTimestamp first, then
// namespace/name. Exactly one side of a duplicate pair yields, so repair
// converges without the two reconciles fighting. Live read, like allocation.
func (r *VPCReconciler) lostVNIToDuplicate(ctx context.Context, vpc *sdnv1alpha1.VPC) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, vniOperationTimeout)
	defer cancel()
	self := vpcClaimKey(vpc)
	lost := false
	err := ipam.WalkClaims(ctx, func(limit int64, token string) ([]sdnv1alpha1.VPC, string, error) {
		var list sdnv1alpha1.VPCList
		err := r.reader().List(ctx, &list, client.Limit(limit), client.Continue(token))
		return list.Items, list.Continue, err
	}, func(o *sdnv1alpha1.VPC) {
		if o.Status.VNI != vpc.Status.VNI || o.Namespace == vpc.Namespace && o.Name == vpc.Name {
			return
		}
		if vpcClaimOlder(vpcClaimKey(o), self) {
			lost = true
		}
	})
	if err != nil {
		return false, fmt.Errorf("list duplicate VPC VNI claims: %w", err)
	}
	return lost, nil
}

type vpcClaim struct {
	created metav1.Time
	name    string // namespace/name, the total-order tiebreak
}

func vpcClaimKey(v *sdnv1alpha1.VPC) vpcClaim {
	return vpcClaim{created: v.CreationTimestamp, name: v.Namespace + "/" + v.Name}
}

// vpcClaimOlder reports whether a precedes b in claim order (total order).
func vpcClaimOlder(a, b vpcClaim) bool {
	if !a.created.Equal(&b.created) {
		return a.created.Before(&b.created)
	}
	return a.name < b.name
}

// SetupWithManager registers the reconciler with the manager.
func (r *VPCReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.VPC{}).
		Named("vpc").
		Complete(r)
}
