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

package tftarget

import (
	"fmt"
	"testing"

	"github.com/GoogleCloudPlatform/config-validator/pkg/targettesting"
)

// reviewTestData is the base test data which will be manifested into a
// raw JSON.
type reviewTestData struct {
	name                string
	match               map[string]interface{}
	address             string
	wantMatch           bool
	wantConstraintError bool
	providerName        string
	removeProviderBlock bool
}

func (td *reviewTestData) jsonAssetTestcase() *targettesting.ReviewTestcase {
	tc := &targettesting.ReviewTestcase{
		Name:                td.name,
		Match:               td.match,
		WantMatch:           td.wantMatch,
		WantConstraintError: td.wantConstraintError,
	}

	providerName := "registry.terraform.io/hashicorp/google"
	if td.providerName != "" {
		providerName = td.providerName
	}

	providerBlock := ""
	if td.removeProviderBlock != true {
		providerBlock = fmt.Sprintf(`
			,"provider_name" : "%s"
		`, providerName)
	}

	tc.Object = targettesting.FromJSON(fmt.Sprintf(`
{
  "name": "test-name",
  "type": "test-asset-type",
  "address": "%s",
  "change": {}
	%s
}
`, td.address, providerBlock))
	return tc
}

var testData = []reviewTestData{
	{
		name:      "Basic",
		address:   "google_compute_global_forwarding_rule.test",
		wantMatch: true,
	},
	{
		name:      "Basic 2 (wildcard)",
		match:     map[string]interface{}{},
		address:   "google_compute_global_forwarding_rule.test",
		wantMatch: true,
	},
	{
		name: "Only match once.",
		match: map[string]interface{}{
			"addresses": []interface{}{"**", "*.*"},
		},
		address:   "google_compute_global_forwarding_rule.test",
		wantMatch: true,
	},
	{
		name: "Match on exact ID",
		match: map[string]interface{}{
			"addresses": []interface{}{"google_compute_global_forwarding_rule.test"},
		},
		address:   "google_compute_global_forwarding_rule.test",
		wantMatch: true,
	},
	{
		name: "Does not match address for nested module",
		match: map[string]interface{}{
			"addresses": []interface{}{"google_compute_global_forwarding_rule.test"},
		},
		address:   "module.abc.google_compute_global_forwarding_rule.test",
		wantMatch: false,
	},
	{
		name: "name wildcard match",
		match: map[string]interface{}{
			"addresses": []interface{}{"google_compute_global_forwarding_rule.*"},
		},
		address:   "google_compute_global_forwarding_rule.test",
		wantMatch: true,
	},
	{
		name: "module wildcard match",
		match: map[string]interface{}{
			"addresses": []interface{}{"**.google_compute_global_forwarding_rule.*"},
		},
		address:   "module.abc.google_compute_global_forwarding_rule.test",
		wantMatch: true,
	},
	{
		name: "root wildcard match",
		match: map[string]interface{}{
			"addresses": []interface{}{"**.google_compute_global_forwarding_rule.*"},
		},
		address:   "root.google_compute_global_forwarding_rule.test",
		wantMatch: true,
	},
	{
		name: "root doesn't match module",
		match: map[string]interface{}{
			"addresses": []interface{}{"module.one.google_compute_global_forwarding_rule.*"},
		},
		address:   "root.google_compute_global_forwarding_rule.test",
		wantMatch: false,
	},
	// exclude tests
	{
		name: "exclude all",
		match: map[string]interface{}{
			"excludedAddresses": []interface{}{"**", "*.*"},
		},
		address:   "google_compute_global_forwarding_rule.test",
		wantMatch: false,
	},
	{
		name: "exclude on exact ID",
		match: map[string]interface{}{
			"excludedAddresses": []interface{}{"google_compute_global_forwarding_rule.test"},
		},
		address:   "google_compute_global_forwarding_rule.test",
		wantMatch: false,
	},
	{
		name: "exclude does not match org for nested module",
		match: map[string]interface{}{
			"excludedAddresses": []interface{}{"google_compute_global_forwarding_rule.test"},
		},
		address:   "module.abc.google_compute_global_forwarding_rule.test",
		wantMatch: true,
	},
	{
		name: "exclude name wildcard match",
		match: map[string]interface{}{
			"excludedAddresses": []interface{}{"google_compute_global_forwarding_rule.*"},
		},
		address:   "google_compute_global_forwarding_rule.test",
		wantMatch: false,
	},
	{
		name: "exclude module wildcard match",
		match: map[string]interface{}{
			"excludedAddresses": []interface{}{"**.google_compute_global_forwarding_rule.*"},
		},
		address:   "module.abc.google_compute_global_forwarding_rule.test",
		wantMatch: false,
	},
	// errors
	{
		name: "nested spaces",
		match: map[string]interface{}{
			"addresses": []interface{}{"**.* *.*"},
		},
		address:             "module.abc.google_compute_global_forwarding_rule.test",
		wantConstraintError: true,
	},
	{
		name: "nested special characters",
		match: map[string]interface{}{
			"addresses": []interface{}{"**$$"},
		},
		address:             "module.abc.google_compute_global_forwarding_rule.test",
		wantConstraintError: true,
	},
	{
		name: "exclude error - nested spaces",
		match: map[string]interface{}{
			"excludedAddresses": []interface{}{"**. * *.*"},
		},
		address:             "module.abc.google_compute_global_forwarding_rule.test",
		wantConstraintError: true,
	},
	{
		name: "exclude error - nested special characters",
		match: map[string]interface{}{
			"excludedAddresses": []interface{}{"**$$"},
		},
		address:             "module.abc.google_compute_global_forwarding_rule.test",
		wantConstraintError: true,
	},
	{
		name:         "provider contains google",
		address:      "google_compute_global_forwarding_rule.test",
		wantMatch:    true,
		providerName: "google",
	},
	{
		name:         "provider doesn't contain google",
		address:      "whatever_compute_global_forwarding_rule.test",
		wantMatch:    true,
		providerName: "whatever",
	},

	{
		name:                "provider block missing",
		address:             "google_compute_global_forwarding_rule.test",
		wantMatch:           true,
		removeProviderBlock: true,
	},

	{
		name: "Bad target type",
		match: map[string]interface{}{
			"addresses": "%#*(*#$(#$)",
		},
		wantConstraintError: true,
	},
	{
		name: "Bad target item type",
		match: map[string]interface{}{
			"addresses": []interface{}{1},
		},
		wantConstraintError: true,
	},
	{
		name: "Bad exclude type",
		match: map[string]interface{}{
			"excludedAddresses": ")$(*#$)*$*&#x",
		},
		wantConstraintError: true,
	},
	{
		name: "Bad exclude item type",
		match: map[string]interface{}{
			"excludedAddresses": []interface{}{1},
		},
		wantConstraintError: true,
	},
}

func TestTargetHandler(t *testing.T) {
	var testcases []*targettesting.ReviewTestcase
	for _, tc := range testData {
		testcases = append(
			testcases,
			tc.jsonAssetTestcase(),
		)
	}

	targettesting.CreateTargetHandler(t, New(), testcases).Test(t)
}
