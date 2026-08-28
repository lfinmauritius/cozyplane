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

package vpngateway

import (
	"context"
	"errors"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"
)

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a VPNGateway.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	gw, ok := obj.(*sdn.VPNGateway)
	if !ok {
		return nil, nil, errors.New("given object is not a VPNGateway")
	}

	return labels.Set(gw.Labels), SelectableFields(gw), nil
}

// MatchVPNGateway is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchVPNGateway(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object.
func SelectableFields(obj *sdn.VPNGateway) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

type vpnGatewayStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy creates and returns a vpnGatewayStrategy instance.
func NewStrategy(typer runtime.ObjectTyper) vpnGatewayStrategy {
	return vpnGatewayStrategy{typer, names.SimpleNameGenerator}
}

func (vpnGatewayStrategy) NamespaceScoped() bool {
	return true
}

func (vpnGatewayStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	gw := obj.(*sdn.VPNGateway)
	gw.Status = sdn.VPNGatewayStatus{}
}

func (vpnGatewayStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newGW := obj.(*sdn.VPNGateway)
	oldGW := old.(*sdn.VPNGateway)
	newGW.Status = oldGW.Status
}

func (vpnGatewayStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (vpnGatewayStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (vpnGatewayStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (vpnGatewayStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (vpnGatewayStrategy) Canonicalize(obj runtime.Object) {
}

func (vpnGatewayStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnUpdate returns warnings for the given update.
func (vpnGatewayStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// vpnGatewayStatusStrategy is the update strategy for the /status subresource:
// it updates status but preserves spec (the mirror image of vpnGatewayStrategy).
type vpnGatewayStatusStrategy struct {
	vpnGatewayStrategy
}

// NewStatusStrategy creates a strategy for the VPNGateway status subresource.
func NewStatusStrategy(strategy vpnGatewayStrategy) vpnGatewayStatusStrategy {
	return vpnGatewayStatusStrategy{strategy}
}

func (vpnGatewayStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newGW := obj.(*sdn.VPNGateway)
	oldGW := old.(*sdn.VPNGateway)
	newGW.Spec = oldGW.Spec
}

func (vpnGatewayStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

func (vpnGatewayStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
