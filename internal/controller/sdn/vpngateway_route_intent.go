package sdn

import (
	"context"
	"errors"
	"slices"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
)

// The caller has completely enumerated, budgeted and filtered these peers.
// Compare only their prefix intent so successful reconciliations do not cycle
// Ready -> Pending -> Ready or erase a healthy leg on every informer event.
func (r *VPNGatewayReconciler) protectRouteIntent(ctx context.Context, gw *sdn.VPNGateway, conns []sdn.VPNConnection) error {
	var desired []sdn.VPCGatewayRouteStatus
	for i := range conns {
		if cidrs := conns[i].Spec.RemoteCIDRs; len(cidrs) != 0 {
			desired = append(desired, sdn.VPCGatewayRouteStatus{CIDRs: cidrs})
		}
	}
	unchanged := len(gw.Status.Routes) == len(desired)
	if unchanged {
		for i := range desired {
			if !slices.Equal(gw.Status.Routes[i].CIDRs, desired[i].CIDRs) {
				unchanged = false
				break
			}
		}
	}
	if unchanged {
		return nil
	}
	routes, err := blackholeVPNRoutes(desired)
	if err != nil {
		return err
	}
	status := sdn.VPNGatewayStatus{Phase: sdn.VPNGatewayPhasePending, Routes: routes}
	for _, condition := range []string{sdn.VPNGatewayConditionApplianceReady, sdn.VPNGatewayConditionAddressAssigned, sdn.VPNGatewayConditionRoutesProgrammed} {
		setVPNGWCondition(&status, condition, false, "ConfigurationPending", "accepted prefixes are blocked until appliance configuration succeeds")
	}
	for i := range status.Conditions {
		status.Conditions[i].ObservedGeneration = gw.Generation
	}
	gw.Status = status
	// Unlike an ordinary best-effort status refresh, a conflict here must
	// stop realization: the protected prefix publication has not succeeded.
	return r.Status().Update(ctx, gw)
}

func (r *VPNGatewayReconciler) configurationFailure(ctx context.Context, gw *sdn.VPNGateway, cause error) (ctrl.Result, error) {
	_, err := r.reportUnready(ctx, gw, "ConfigurationFailed", "appliance configuration failed; accepted prefixes remain blocked")
	return ctrl.Result{}, errors.Join(cause, err)
}
