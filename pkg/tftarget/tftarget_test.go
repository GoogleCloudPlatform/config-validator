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
	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
)

// match creates a match struct as would exist in a FCV constraint
func match(opts ...func(map[string]interface{})) map[string]interface{} {
	var matchBlock = map[string]interface{}{}
	matchBlock["resource_address"] = map[string]interface{}{}

	for _, opt := range opts {
		opt(matchBlock)
	}

	var destructured interface{} = matchBlock
	return destructured.(map[string]interface{})
}

func stringToInterface(s []string) []interface{} {
	iface := make([]interface{}, len(s))
	for i := range s {
		iface[i] = s[i]
	}
	return iface
}

// includeAddress populates the includeAddress field inside of the match block
func includeAddress(val ...string) func(map[string]interface{}) {
	return func(matchBlock map[string]interface{}) {
		matchBlock["addresses"] = stringToInterface(val)
	}
}

// excludeAddress populates the excludeAddress field inside of the match block
func excludeAddress(val ...string) func(map[string]interface{}) {
	return func(matchBlock map[string]interface{}) {
		matchBlock["excludedAddresses"] = stringToInterface(val)
	}
}

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
	if td.match != nil {
		tc.Match = td.match
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
		match:     match(),
		address:   "google_compute_global_forwarding_rule.test",
		wantMatch: true,
	},
	{
		name:      "Only match once.",
		match:     match(includeAddress("**", "*.*")),
		address:   "google_compute_global_forwarding_rule.test",
		wantMatch: true,
	},
	{
		name:      "Match on exact ID",
		match:     match(includeAddress("google_compute_global_forwarding_rule.test")),
		address:   "google_compute_global_forwarding_rule.test",
		wantMatch: true,
	},
	{
		name:      "Does not match address for nested module",
		match:     match(includeAddress("google_compute_global_forwarding_rule.test")),
		address:   "module.abc.google_compute_global_forwarding_rule.test",
		wantMatch: false,
	},
	{
		name:      "name wildcard match",
		match:     match(includeAddress("google_compute_global_forwarding_rule.*")),
		address:   "google_compute_global_forwarding_rule.test",
		wantMatch: true,
	},
	{
		name:      "module wildcard match",
		match:     match(includeAddress("**.google_compute_global_forwarding_rule.*")),
		address:   "module.abc.google_compute_global_forwarding_rule.test",
		wantMatch: true,
	},
	// exlude tests
	{
		name:      "exclude all",
		match:     match(excludeAddress("**", "*.*")),
		address:   "google_compute_global_forwarding_rule.test",
		wantMatch: false,
	},
	{
		name:      "exclude on exact ID",
		match:     match(excludeAddress("google_compute_global_forwarding_rule.test")),
		address:   "google_compute_global_forwarding_rule.test",
		wantMatch: false,
	},
	{
		name:      "exclude does not match org for nested module",
		match:     match(excludeAddress("google_compute_global_forwarding_rule.test")),
		address:   "module.abc.google_compute_global_forwarding_rule.test",
		wantMatch: true,
	},
	{
		name:      "exclude name wildcard match",
		match:     match(excludeAddress("google_compute_global_forwarding_rule.*")),
		address:   "google_compute_global_forwarding_rule.test",
		wantMatch: false,
	},
	{
		name:      "exclude module wildcard match",
		match:     match(excludeAddress("**.google_compute_global_forwarding_rule.*")),
		address:   "module.abc.google_compute_global_forwarding_rule.test",
		wantMatch: false,
	},
	// errors
	{
		name:                "nested spaces",
		match:               match(includeAddress("**.* *.*")),
		address:             "module.abc.google_compute_global_forwarding_rule.test",
		wantConstraintError: true,
	},
	{
		name:                "nested special characters",
		match:               match(includeAddress("**$$")),
		address:             "module.abc.google_compute_global_forwarding_rule.test",
		wantConstraintError: true,
	},
	{
		name:                "exclude error - nested spaces",
		match:               match(excludeAddress("**. * *.*")),
		address:             "module.abc.google_compute_global_forwarding_rule.test",
		wantConstraintError: true,
	},
	{
		name:                "exclude error - nested special characters",
		match:               match(excludeAddress("**$$")),
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
		address:      "google_compute_global_forwarding_rule.test",
		wantMatch:    false,
		providerName: "moogle",
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
	var targetHandlerTest = targettesting.TargetHandlerTest{
		NewTargetHandler: func(t *testing.T) client.TargetHandler {
			return New()
		},
	}

	for _, tc := range testData {
		targetHandlerTest.ReviewTestcases = append(
			targetHandlerTest.ReviewTestcases,
			tc.jsonAssetTestcase(),
		)
	}
	targetHandlerTest.Test(t)

}
