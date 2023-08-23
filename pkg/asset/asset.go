// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package asset

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/GoogleCloudPlatform/config-validator/pkg/api/validator"
	"github.com/GoogleCloudPlatform/config-validator/pkg/gcv/configs"
	"github.com/golang/glog"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/encoding/protojson"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const logRequestsVerboseLevel = 2

func ValidateAsset(asset *validator.Asset) error {
	var result *multierror.Error
	if asset.GetName() == "" {
		result = multierror.Append(result, errors.New("missing asset name"))
	}
	if asset.GetAncestryPath() == "" {
		result = multierror.Append(result, errors.Errorf("asset %q missing ancestry path", asset.GetName()))
	}
	if asset.GetAssetType() == "" {
		result = multierror.Append(result, errors.Errorf("asset %q missing type", asset.GetName()))
	}
	if asset.GetResource() == nil && asset.GetIamPolicy() == nil && asset.GetOrgPolicy() == nil && asset.GetAccessContextPolicy() == nil && asset.GetV2OrgPolicies() == nil {
		result = multierror.Append(result, errors.Errorf("asset %q missing all of these: resource, IAM policy, Org Policy, Access Context Policy, v2 Org Policy", asset.GetName()))
	}
	return result.ErrorOrNil()
}

func ConvertResourceViaJSONToInterface(asset *validator.Asset) (interface{}, error) {
	if asset == nil {
		return nil, nil
	}
	m := &protojson.MarshalOptions{
		UseProtoNames: true,
	}
	if asset.Resource != nil {
		CleanStructValue(asset.Resource.Data)
	}
	glog.V(logRequestsVerboseLevel).Infof("converting asset to golang interface: %v", asset)
	buf, err := m.Marshal(asset)
	if err != nil {
		return nil, errors.Wrapf(err, "marshalling to json with asset %s: %v", asset.Name, asset)
	}
	var f interface{}
	if err := json.Unmarshal(buf, &f); err != nil {
		return nil, errors.Wrapf(err, "marshalling from json with asset %s: %v", asset.Name, asset)
	}
	return f, nil
}

// SanitizeAncestryPath will populate the AncestryPath field from the ancestors list, or fix the pre-populated one
// if no ancestry list is provided.
func SanitizeAncestryPath(asset *validator.Asset) error {
	if len(asset.Ancestors) != 0 {
		asset.AncestryPath = AncestryPath(asset.Ancestors)
		return nil
	}

	if asset.AncestryPath != "" {
		asset.AncestryPath = configs.NormalizeAncestry(asset.AncestryPath)
		return nil
	}

	return errors.Errorf("no ancestry information for asset %s", asset.String())
}

// AncestryPath returns the ancestry path from a given ancestors list
func AncestryPath(ancestors []string) string {
	cnt := len(ancestors)
	revAncestors := make([]string, len(ancestors))
	for idx := 0; idx < cnt; idx++ {
		revAncestors[cnt-idx-1] = ancestors[idx]
	}
	return strings.Join(revAncestors, "/")
}

// ConvertCAIToK8s will convert a supported CAI Asset to a K8S resource and populate any omitted fields.
func ConvertCAIToK8s(asset map[string]interface{}) (*unstructured.Unstructured, error) {
	groupKind, found, err := unstructured.NestedString(asset, "asset_type")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to access asset_type field")
	}
	if !found {
		return nil, errors.Errorf("asset_type field not found")
	}

	parts := strings.Split(groupKind, "/")
	if len(parts) != 2 {
		return nil, errors.Errorf("expected asset_type to be of form \"<group>/<kind>\", got %s", groupKind)
	}

	group := parts[0]
	kind := parts[1]
	// CAI pretends that the core resources are part of the "k8s.io" apiGroup.  For compatibility with what one would
	// see in kubernetes, we set the group to empty string ("").
	if group == "k8s.io" {
		group = ""
	}

	version, found, err := unstructured.NestedString(asset, "resource", "version")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to access resource.version field")
	}
	if !found {
		return nil, errors.Errorf("resource.version field not found")
	}

	resource, found, err := unstructured.NestedMap(asset, "resource", "data")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to access resource.data field")
	}
	if !found {
		return nil, errors.Errorf("resource.data field not found")
	}

	u := &unstructured.Unstructured{Object: resource}
	u.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   group,
		Version: version,
		Kind:    kind,
	})

	ancestors, found, err := unstructured.NestedStringSlice(asset, "ancestors")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to access ancestors field")
	}
	if !found {
		return nil, errors.Errorf("ancestors field not found")
	}

	annotations := u.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations["validator.forsetisecurity.org/ancestorPath"] = AncestryPath(ancestors)
	u.SetAnnotations(annotations)

	return u, nil
}

// ConvertToAdmissionRequest converts a CAI asset containing a K8S type to an AdmissionRequest which is the format that
// the Gatekeeper Constraint Framework target expects.
func ConvertToAdmissionRequest(asset map[string]interface{}) (*admissionv1beta1.AdmissionRequest, error) {
	resource, err := ConvertCAIToK8s(asset)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert CAI asset to k8s resource")
	}

	resourceJSON, err := json.Marshal(resource.Object)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal k8s resource (converted from CAI asset) to JSON")
	}

	gvk := resource.GroupVersionKind()
	req := &admissionv1beta1.AdmissionRequest{
		Kind: metav1.GroupVersionKind{
			Group:   gvk.Group,
			Version: gvk.Version,
			Kind:    gvk.Kind,
		},
		Object: runtime.RawExtension{
			Raw: resourceJSON,
		},
		Name: resource.GetName(),
	}
	return req, nil
}

// k8s assset names will follow pattern:
// //container.googleapis.com/projects/*/(locations|zones)/*/clusters/*/k8s
var assetPath = regexp.MustCompile(`^//container/.googleapis/.com/projects/[^/]*/(locations|zones)/[^/]*/clusters/[^/]*/k8s`)

// IsK8S returns true if the CAI asset is an asset from a kubernetes cluster.
func IsK8S(asset map[string]interface{}) bool {
	assetName, found, err := unstructured.NestedString(asset, "name")
	if !found || err != nil {
		return false
	}
	return assetPath.MatchString(assetName)
}
