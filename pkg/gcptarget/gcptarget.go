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

// Package gcptarget is a constraint framework target for config-validator to use for integrating with the opa constraint framework.
package gcptarget

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/GoogleCloudPlatform/config-validator/pkg/api/validator"
	asset2 "github.com/GoogleCloudPlatform/config-validator/pkg/asset"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Name is the target name for GCPTarget
const Name = "validation.gcp.forsetisecurity.org"

// GCPTarget is the constraint framework target for CAI asset data
type GCPTarget struct {
}

var _ handler.TargetHandler = &GCPTarget{}

// New returns a new GCPTarget
func New() *GCPTarget {
	return &GCPTarget{}
}

// ToMatcher converts .spec.match in mutators to Matcher.
func (h *GCPTarget) ToMatcher(constraint *unstructured.Unstructured) (constraints.Matcher, error) {
	match, ok, err := unstructured.NestedMap(constraint.Object, "spec", "match")
	if err != nil {
		return nil, fmt.Errorf("unable to get spec.match: %w", err)
	}
	if !ok {
		return &matcher{ancestries: []string{"**"}, excludedAncestries: []string{}}, nil
	}

	include, ok, err := unstructured.NestedStringSlice(match, "ancestries")
	if err != nil {
		return nil, fmt.Errorf("unable to get string slice from spec.match.ancestries: %w", err)
	}
	if !ok {
		include, ok, err = unstructured.NestedStringSlice(match, "target")
		if err != nil {
			return nil, fmt.Errorf("unable to get string slice from spec.match.target: %w", err)
		}
		if !ok {
			include = []string{"**"}
		}
	}

	exclude, ok, err := unstructured.NestedStringSlice(match, "excludedAncestries")
	if err != nil {
		return nil, fmt.Errorf("unable to get string slice from spec.match.excludedAncestries: %w", err)
	}
	if !ok {
		exclude, ok, err = unstructured.NestedStringSlice(match, "exclude")
		if err != nil {
			return nil, fmt.Errorf("unable to get string slice from spec.match.exclude: %w", err)
		}
		if !ok {
			exclude = []string{}
		}
	}

	return &matcher{
		ancestries:         include,
		excludedAncestries: exclude,
	}, nil
}

// MatchSchema implements client.MatchSchemaProvider
func (g *GCPTarget) MatchSchema() apiextensions.JSONSchemaProps {
	return apiextensions.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextensions.JSONSchemaProps{
			"target": {
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
			"ancestries": {
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{
						Type: "string",
					},
				},
			},
			"excludedAncestries": {
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{
						Type: "string",
					},
				},
			},
		},
	}
}

// GetName implements handler.TargetHandler
func (g *GCPTarget) GetName() string {
	return Name
}

// ProcessData implements handler.TargetHandler
func (g *GCPTarget) ProcessData(obj interface{}) (bool, []string, interface{}, error) {
	return false, nil, nil, errors.New("storing data for referential constraint eval is not supported at this time.")
}

// HandleReview implements handler.TargetHandler
func (g *GCPTarget) HandleReview(obj interface{}) (bool, interface{}, error) {
	switch asset := obj.(type) {
	case *validator.Asset:
		return g.handleAsset(asset)
	case map[string]interface{}:
		if _, found, err := unstructured.NestedString(asset, "name"); !found || err != nil {
			return false, nil, err
		}
		if _, found, err := unstructured.NestedString(asset, "asset_type"); !found || err != nil {
			return false, nil, err
		}
		if _, found, err := unstructured.NestedString(asset, "ancestry_path"); !found || err != nil {
			return false, nil, err
		}
		_, foundResource, err := unstructured.NestedMap(asset, "resource")
		if err != nil {
			return false, nil, err
		}
		_, foundIam, err := unstructured.NestedMap(asset, "iam_policy")
		if err != nil {
			return false, nil, err
		}
		foundOrgPolicy := false
		if asset["org_policy"] != nil {
			foundOrgPolicy = true
		}
		foundV2OrgPolicy := false
		if asset["v2_org_policies"] != nil {
			foundV2OrgPolicy = true
		}
		_, foundAccessPolicy, err := unstructured.NestedMap(asset, "access_policy")
		if err != nil {
			return false, nil, err
		}
		_, foundAcessLevel, err := unstructured.NestedMap(asset, "access_level")
		if err != nil {
			return false, nil, err
		}
		_, foundServicePerimeter, err := unstructured.NestedMap(asset, "service_perimeter")
		if err != nil {
			return false, nil, err
		}

		if !foundIam && !foundResource && !foundOrgPolicy && !foundV2OrgPolicy && !foundAccessPolicy && !foundAcessLevel && !foundServicePerimeter {
			return false, nil, nil
		}
		resourceTypes := 0
		if foundResource {
			resourceTypes++
		}
		if foundIam {
			resourceTypes++
		}
		if foundOrgPolicy {
			resourceTypes++
		}
		if foundV2OrgPolicy {
			resourceTypes++
		}
		if foundAccessPolicy {
			resourceTypes++
		}
		if foundAcessLevel {
			resourceTypes++
		}
		if foundServicePerimeter {
			resourceTypes++
		}
		if resourceTypes > 1 {
			return false, nil, fmt.Errorf("malformed asset has more than one of: resource, iam policy, org policy, access context policy: %v", asset)
		}
		return true, asset, nil
	}
	return false, nil, nil
}

// handleAsset handles input from CAI assets as received via the gRPC interface.
func (g *GCPTarget) handleAsset(asset *validator.Asset) (bool, interface{}, error) {
	if asset.Resource == nil {
		return false, nil, fmt.Errorf("CAI asset's resource field is nil %s", asset)
	}
	asset2.CleanStructValue(asset.Resource.Data)
	m := &jsonpb.Marshaler{
		OrigName: true,
	}
	var buf bytes.Buffer
	if err := m.Marshal(&buf, asset); err != nil {
		return false, nil, fmt.Errorf("marshalling to json with asset %s: %v. %w", asset.Name, asset, err)
	}
	var f interface{}
	err := json.Unmarshal(buf.Bytes(), &f)
	if err != nil {
		return false, nil, fmt.Errorf("marshalling from json with asset %s: %v. %w", asset.Name, asset, err)
	}
	return true, f, nil
}

// HandleViolation implements handler.TargetHandler
func (g *GCPTarget) HandleViolation(result *types.Result) error {
	return nil
}

/*
cases
organizations/*
organizations/[0-9]+/*
organizations/[0-9]+/folders/*
organizations/[0-9]+/folders/[0-9]+/*
organizations/[0-9]+/folders/[0-9]+/projects/*
organizations/[0-9]+/folders/[0-9]+/projects/[0-9]+
folders/*
folders/[0-9]+/*
folders/[0-9]+/projects/*
folders/[0-9]+/projects/[0-9]+
projects/*
projects/[0-9]+
*/

const (
	organization = "organizations"
	folder       = "folders"
	project      = "projects"
)

const (
	stateStart   = "stateStart"
	stateFolder  = "stateFolder"
	stateProject = "stateProject"
)

var numberRegex = regexp.MustCompile(`^[0-9]+\*{0,2}$`)

// From https://cloud.google.com/resource-manager/docs/creating-managing-projects:
// The project ID must be a unique string of 6 to 30 lowercase letters, digits, or hyphens. It must start with a letter, and cannot have a trailing hyphen.
var projectIDRegex = regexp.MustCompile(`^[a-z][a-z0-9-]{5,27}[a-z0-9]$`)

// checkPathGlob
func checkPathGlob(expression string) error {
	// check for path components / numbers
	parts := strings.Split(expression, "/")
	state := stateStart
	for i := 0; i < len(parts); i++ {
		item := parts[i]
		switch {
		case item == organization:
			if state != stateStart {
				return fmt.Errorf("unexpected %s element %d in %s", item, i, expression)
			}
			state = stateFolder
		case item == folder:
			if state != stateStart && state != stateFolder {
				return fmt.Errorf("unexpected %s element %d in %s", item, i, expression)
			}
			state = stateFolder
		case item == project:
			state = stateProject
		case item == "*":
		case item == "**":
		case item == "unknown":
		case numberRegex.MatchString(item):
		case state == stateProject && projectIDRegex.MatchString(item):
		default:
			return fmt.Errorf("unexpected item %s element %d in %s", item, i, expression)
		}
	}
	return nil
}

func checkPathGlobs(rs []string) error {
	for idx, r := range rs {
		if err := checkPathGlob(r); err != nil {
			return fmt.Errorf("idx [%d]: %w", idx, err)
		}
	}
	return nil
}

// ValidateConstraint implements handler.TargetHandler
func (g *GCPTarget) ValidateConstraint(constraint *unstructured.Unstructured) error {
	ancestries, ancestriesFound, ancestriesErr := unstructured.NestedStringSlice(constraint.Object, "spec", "match", "ancestries")
	targets, targetsFound, targetsErr := unstructured.NestedStringSlice(constraint.Object, "spec", "match", "target")
	if ancestriesFound && targetsFound {
		return errors.New("only one of spec.match.ancestries and spec.match.target can be specified")
	} else if ancestriesFound {
		if ancestriesErr != nil {
			return fmt.Errorf("invalid spec.match.ancestries: %s", ancestriesErr)
		}
		if ancestriesErr := checkPathGlobs(ancestries); ancestriesErr != nil {
			return fmt.Errorf("invalid glob in spec.match.ancestries: %w", ancestriesErr)
		}
	} else if targetsFound {
		// TODO b/232980918: replace with zapLogger.Warn
		log.Print(
			"spec.match.target is deprecated and will be removed in a future release. Use spec.match.ancestries instead",
		)
		if targetsErr != nil {
			return fmt.Errorf("invalid spec.match.target: %s", targetsErr)
		}
		if targetsErr := checkPathGlobs(targets); targetsErr != nil {
			return fmt.Errorf("invalid glob in spec.match.target: %w", targetsErr)
		}
	}

	excludedAncestries, excludedAncestriesFound, excludedAncestriesErr := unstructured.NestedStringSlice(constraint.Object, "spec", "match", "excludedAncestries")
	excludes, excludesFound, excludesErr := unstructured.NestedStringSlice(constraint.Object, "spec", "match", "exclude")
	if excludedAncestriesFound && excludesFound {
		return errors.New("only one of spec.match.excludedAncestries and spec.match.exclude can be specified")
	} else if excludedAncestriesFound {
		if excludedAncestriesErr != nil {
			return fmt.Errorf("invalid spec.match.excludedAncestries: %s", excludedAncestriesErr)
		}
		if excludedAncestriesErr := checkPathGlobs(excludedAncestries); excludedAncestriesErr != nil {
			return fmt.Errorf("invalid glob in spec.match.excludedAncestries: %w", excludedAncestriesErr)
		}
	} else if excludesFound {
		// TODO b/232980918: replace with zapLogger.Warn
		log.Print(
			"spec.match.exclude is deprecated and will be removed in a future release. Use spec.match.excludedAncestries instead",
		)
		if excludesErr != nil {
			return fmt.Errorf("invalid spec.match.exclude: %s", excludesErr)
		}
		if excludesErr := checkPathGlobs(excludes); excludesErr != nil {
			return fmt.Errorf("invalid glob in spec.match.exclude: %w", excludesErr)
		}
	}
	return nil
}
