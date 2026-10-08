package main

import (
	"context"
	"log/slog"
	"net"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/podrepair"
	localclientset "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned"
)

// A Pod status address alone does not authorize reclaiming an IP. Require the
// same address in a successfully rebuilt local endpoint, and never adopt a
// conflicting claim. Legacy aliases repair with no invented sandbox identity.
func healLocalFabricIPs(ctx context.Context, core kubernetes.Interface, local localclientset.Interface, node string, rebuilt []datapath.LocalFabricIP, log *slog.Logger) error {
	ctx, cancel := context.WithTimeout(ctx, startupBestEffortTimeout)
	defer cancel()
	endpoints := map[string]datapath.LocalFabricIP{}
	ambiguous := map[string]bool{}
	for _, endpoint := range rebuilt {
		if ip := net.ParseIP(endpoint.Address); ip != nil {
			address := ip.String()
			if previous, exists := endpoints[address]; exists && (previous.ContainerID != endpoint.ContainerID || previous.IfName != endpoint.IfName) {
				ambiguous[address] = true
			}
			endpoints[address] = endpoint
		}
	}
	candidates := make(map[string]struct{}, len(endpoints))
	for address := range endpoints {
		if !ambiguous[address] {
			candidates[address] = struct{}{}
		} else {
			log.Warn("fabric repair refused ambiguous sandbox ownership", "address", address)
		}
	}
	pods, err := podrepair.ListLocalRunningPodAddresses(ctx, core, node, candidates)
	if err != nil {
		return err
	}
	for _, pod := range pods {
		endpoint := endpoints[pod.Address]
		name := localv1alpha1.FabricIPName(pod.Address)
		existing, err := local.LocalV1alpha1().FabricIPs().Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			if existing.Spec.PodUID != pod.UID || existing.Spec.Node != node {
				log.Warn("fabric repair refused conflicting claim", "claim", name, "pod", pod.Namespace+"/"+pod.Name)
			}
			continue
		}
		if !apierrors.IsNotFound(err) {
			return err
		}
		claim := &localv1alpha1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"local.sdn.cozystack.io/pod-uid": pod.UID, "local.sdn.cozystack.io/pod-namespace": pod.Namespace, "local.sdn.cozystack.io/node": node}}, Spec: localv1alpha1.FabricIPSpec{Address: pod.Address, Node: node, PodNamespace: pod.Namespace, PodName: pod.Name, PodUID: pod.UID, ContainerID: endpoint.ContainerID, IfName: endpoint.IfName}}
		if _, err := local.LocalV1alpha1().FabricIPs().Create(ctx, claim, metav1.CreateOptions{}); err != nil {
			if apierrors.IsAlreadyExists(err) {
				continue
			}
			return err
		}
		log.Warn("recreated missing FabricIP from rebuilt local endpoint", "address", pod.Address, "pod", pod.Namespace+"/"+pod.Name, "sandboxKnown", strings.TrimSpace(endpoint.ContainerID) != "")
	}
	return nil
}
