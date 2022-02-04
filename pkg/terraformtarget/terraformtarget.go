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

// Package terraformtarget is a constraint framework target for FCV to use for integrating with the opa constraint framework.
package terraformtarget

import (
	"regexp"
	"strings"
	"text/template"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/pkg/errors"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Name is the target name for TerraformTarget
const Name = "validation.terraform.forsetisecurity.org"

// TerraformTarget is the constraint framework target for FCV
type TerraformTarget struct {
}

var _ client.TargetHandler = &TerraformTarget{}

// New returns a new TerraformTarget
func New() *TerraformTarget {
	return &TerraformTarget{}
}

// MatchSchema implements client.MatchSchemaProvider
func (g *TerraformTarget) MatchSchema() apiextensions.JSONSchemaProps {
	return apiextensions.JSONSchemaProps{
		Properties: map[string]apiextensions.JSONSchemaProps{
			"resource_address": {
				Type: "object",
				Properties: map[string]apiextensions.JSONSchemaProps{
					"include": {
						Type: "array",
						Items: &apiextensions.JSONSchemaPropsOrArray{
							Schema: &apiextensions.JSONSchemaProps{
								Type: "string",
							},
						},
					},
					"exclude": {
						Type: "array",
						Items: &apiextensions.JSONSchemaPropsOrArray{
							Schema: &apiextensions.JSONSchemaProps{
								Type: "string",
							},
						},
					},
				},
			},
		},
	}
}

// GetName implements client.TargetHandler
func (g *TerraformTarget) GetName() string {
	return Name
}

// Library implements client.TargetHandler
func (g *TerraformTarget) Library() *template.Template {
	return libraryTemplate
}

// ProcessData implements client.TargetHandler
func (g *TerraformTarget) ProcessData(obj interface{}) (bool, string, interface{}, error) {
	return false, "", nil, errors.Errorf("Storing data for referential constraint eval is not supported at this time.")
}

// HandleReview implements client.TargetHandler
func (g *TerraformTarget) HandleReview(obj interface{}) (bool, interface{}, error) {
	switch resource := obj.(type) {
	case map[string]interface{}:
		if _, found, err := unstructured.NestedString(resource, "name"); !found || err != nil {
			return false, nil, err
		}
		if _, found, err := unstructured.NestedString(resource, "address"); !found || err != nil {
			return false, nil, err
		}
		if _, found, err := unstructured.NestedStringMap(resource, "change"); !found || err != nil {
			return false, nil, err
		}
		if _, found, err := unstructured.NestedString(resource, "type"); !found || err != nil {
			return false, nil, err
		}
		if _, found, err := unstructured.NestedString(resource, "provider_name"); !found || err != nil {
			return false, nil, err
		}
		return true, resource, nil
	}
	return false, nil, nil
}

// HandleViolation implements client.TargetHandler
func (g *TerraformTarget) HandleViolation(result *types.Result) error {
	result.Resource = result.Review
	return nil
}

var partRegex = regexp.MustCompile(`[\w.\-_\[\]\d]+`)

// checkPathGlob
func checkPathGlob(expression string) error {
	// check for path components / numbers
	parts := strings.Split(expression, ".")
	for i := 0; i < len(parts); i++ {
		item := parts[i]
		switch {
		case item == "*":
		case item == "**":
		case partRegex.MatchString(item):
		default:
			return errors.Errorf("unexpected item %s element %d in %s", item, i, expression)
		}
	}
	return nil
}

func checkPathGlobs(rs []string) error {
	for idx, r := range rs {
		if err := checkPathGlob(r); err != nil {
			return errors.Wrapf(err, "idx: %d", idx)
		}
	}
	return nil
}

// ValidateConstraint implements client.TargetHandler
func (g *TerraformTarget) ValidateConstraint(constraint *unstructured.Unstructured) error {
	includes, found, err := unstructured.NestedStringSlice(constraint.Object, "spec", "match", "resource_address", "include")
	if err != nil {
		return errors.Errorf("invalid spec.match.target: %s", err)
	}
	if found {
		if err := checkPathGlobs(includes); err != nil {
			return errors.Wrapf(err, "invalid glob in target")
		}
	}
	excludes, found, err := unstructured.NestedStringSlice(constraint.Object, "spec", "match", "resource_address", "exclude")
	if err != nil {
		return errors.Errorf("invalid spec.match.exclude: %s", err)
	}
	if found {
		if err := checkPathGlobs(excludes); err != nil {
			return errors.Wrapf(err, "invalid glob in exclude")
		}
	}
	return nil
}
