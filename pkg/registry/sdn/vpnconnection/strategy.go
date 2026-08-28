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

package vpnconnection

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

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a VPNConnection.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	conn, ok := obj.(*sdn.VPNConnection)
	if !ok {
		return nil, nil, errors.New("given object is not a VPNConnection")
	}

	return labels.Set(conn.Labels), SelectableFields(conn), nil
}

// MatchVPNConnection is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchVPNConnection(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object.
func SelectableFields(obj *sdn.VPNConnection) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

type vpnConnectionStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy creates and returns a vpnConnectionStrategy instance.
func NewStrategy(typer runtime.ObjectTyper) vpnConnectionStrategy {
	return vpnConnectionStrategy{typer, names.SimpleNameGenerator}
}

func (vpnConnectionStrategy) NamespaceScoped() bool {
	return true
}

func (vpnConnectionStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	conn := obj.(*sdn.VPNConnection)
	conn.Status = sdn.VPNConnectionStatus{}
}

func (vpnConnectionStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newConn := obj.(*sdn.VPNConnection)
	oldConn := old.(*sdn.VPNConnection)
	newConn.Status = oldConn.Status
}

func (vpnConnectionStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (vpnConnectionStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (vpnConnectionStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (vpnConnectionStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (vpnConnectionStrategy) Canonicalize(obj runtime.Object) {
}

func (vpnConnectionStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnUpdate returns warnings for the given update.
func (vpnConnectionStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// vpnConnectionStatusStrategy is the update strategy for the /status subresource:
// it updates status but preserves spec (the mirror image of vpnConnectionStrategy).
type vpnConnectionStatusStrategy struct {
	vpnConnectionStrategy
}

// NewStatusStrategy creates a strategy for the VPNConnection status subresource.
func NewStatusStrategy(strategy vpnConnectionStrategy) vpnConnectionStatusStrategy {
	return vpnConnectionStatusStrategy{strategy}
}

func (vpnConnectionStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newConn := obj.(*sdn.VPNConnection)
	oldConn := old.(*sdn.VPNConnection)
	newConn.Spec = oldConn.Spec
}

func (vpnConnectionStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

func (vpnConnectionStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
