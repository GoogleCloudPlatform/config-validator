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

package terraformtarget

import (
	"fmt"
	"testing"
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
	temp := map[string]interface{}{
		"include": stringToInterface(val),
	}
	return func(matchBlock map[string]interface{}) {
		matchBlock["resource_address"] = temp
	}
}

// excludeAddress populates the excludeAddress field inside of the match block
func excludeAddress(val ...string) func(map[string]interface{}) {
	temp := map[string]interface{}{
		"exclude": stringToInterface(val),
	}
	return func(matchBlock map[string]interface{}) {
		matchBlock["resource_address"] = temp
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
}

func (td *reviewTestData) jsonAssetTestcase() *ReviewTestcase {
	tc := &ReviewTestcase{
		Name:                td.name,
		Match:               td.match,
		WantMatch:           td.wantMatch,
		WantConstraintError: td.wantConstraintError,
	}
	if td.match != nil {
		tc.Match = td.match
	}

	tc.Object = FromJSON(fmt.Sprintf(`
{
  "name": "test-name",
  "type": "test-asset-type",
  "address": "%s",
  "change": {},
	"provider_name" : "registry.terraform.io/hashicorp/google"
}
`, td.address))
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
		name:      "Does not match org for nested module",
		match:     match(includeAddress("google_compute_global_forwarding_rule.test")),
		address:   "module.abc.google_compute_global_forwarding_rule.test",
		wantMatch: false,
	},
	{
		name:      "Does not match org for nested module",
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
		name:                "exclud error - nested spaces",
		match:               match(excludeAddress("**. * *.*")),
		address:             "module.abc.google_compute_global_forwarding_rule.test",
		wantConstraintError: true,
	},
	{
		name:                "exclud error - nested special characters",
		match:               match(excludeAddress("**$$")),
		address:             "module.abc.google_compute_global_forwarding_rule.test",
		wantConstraintError: true,
	},
}

func TestTargetHandler(t *testing.T) {
	for _, testData := range testData {
		testcase := testData.jsonAssetTestcase()
		testcase.Test(t)
	}
}
