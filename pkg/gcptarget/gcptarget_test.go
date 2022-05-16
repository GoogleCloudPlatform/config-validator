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

package gcptarget

import (
	"fmt"
	"testing"

	"github.com/GoogleCloudPlatform/config-validator/pkg/api/validator"
	"github.com/GoogleCloudPlatform/config-validator/pkg/targettesting"
	targetHandlerTest "github.com/GoogleCloudPlatform/config-validator/pkg/targettesting"
	v1 "google.golang.org/genproto/googleapis/cloud/asset/v1"
)

// asset creates an CAI asset with the given ancestry path.
func asset(ancestryPath string) func(t *testing.T) interface{} {
	return func(t *testing.T) interface{} {
		return &validator.Asset{
			AncestryPath: ancestryPath,
			Resource:     &v1.Resource{},
		}
	}
}

// reviewTestData is the base test data which will be manifested into a
// fcv asset and raw JSON variant.
type reviewTestData struct {
	name                string
	match               map[string]interface{}
	ancestryPath        string
	wantMatch           bool
	wantConstraintError bool
}

func (td *reviewTestData) jsonAssetTestcase() *targetHandlerTest.ReviewTestcase {
	tc := &targetHandlerTest.ReviewTestcase{
		Name:                "json " + td.name,
		Match:               td.match,
		WantMatch:           td.wantMatch,
		WantConstraintError: td.wantConstraintError,
	}
	tc.Object = targetHandlerTest.FromJSON(fmt.Sprintf(`
{
  "name": "test-name",
  "asset_type": "test-asset-type",
  "ancestry_path": "%s",
  "resource": {}
}
`, td.ancestryPath))
	return tc
}

func (td *reviewTestData) assetTestcase() *targetHandlerTest.ReviewTestcase {
	tc := &targetHandlerTest.ReviewTestcase{
		Name:                "asset " + td.name,
		Match:               td.match,
		WantMatch:           td.wantMatch,
		WantConstraintError: td.wantConstraintError,
	}
	tc.Object = asset(td.ancestryPath)
	return tc
}

func (td *reviewTestData) legacySpecMatchTestcase() *targetHandlerTest.ReviewTestcase {
	legacyMatch := map[string]interface{}{}

	if ancestries, ok := td.match["ancestries"]; ok {
		legacyMatch["target"] = ancestries
	}
	if excludedAncestries, ok := td.match["excludedAncestries"]; ok {
		legacyMatch["exclude"] = excludedAncestries
	}

	tc := &targetHandlerTest.ReviewTestcase{
		Name:                "legacy spec match " + td.name,
		Match:               legacyMatch,
		WantMatch:           td.wantMatch,
		WantConstraintError: td.wantConstraintError,
	}
	tc.Object = asset(td.ancestryPath)
	return tc
}

var matchTests = []reviewTestData{
	{
		name:         "Null match object (matches anything)",
		ancestryPath: "organizations/123454321/folders/1221214",
		wantMatch:    true,
	},
	{
		name:         "No match specified (matches anything)",
		match:        map[string]interface{}{},
		ancestryPath: "organizations/123454321/folders/1221214",
		wantMatch:    true,
	},
	{
		name: "Only match once.",
		match: map[string]interface{}{
			"ancestries": []interface{}{"**", "organizations/**"},
		},
		ancestryPath: "organizations/123454321/folders/1221214",
		wantMatch:    true,
	},
	{
		name: "Match org on exact ID",
		match: map[string]interface{}{
			"ancestries": []interface{}{"organizations/123454321"},
		},
		ancestryPath: "organizations/123454321",
		wantMatch:    true,
	},
	{
		name: "Does not match org for descendant match",
		match: map[string]interface{}{
			"ancestries": []interface{}{"organizations/123454321/**"},
		},
		ancestryPath: "organizations/123454321",
		wantMatch:    false,
	},
	{
		name: "No match org on close ID",
		match: map[string]interface{}{
			"ancestries": []interface{}{"organizations/123454321/*"},
		},
		ancestryPath: "organizations/1234543211",
		wantMatch:    false,
	},
	{
		name: "Match all under org ID - folder",
		match: map[string]interface{}{
			"ancestries": []interface{}{"organizations/123454321/**"},
		},
		ancestryPath: "organizations/123454321/folders/1242511",
		wantMatch:    true,
	},
	{
		name: "Match all under org ID - project",
		match: map[string]interface{}{
			"ancestries": []interface{}{"organizations/123454321/**"},
		},
		ancestryPath: "organizations/123454321/projects/1242511",
		wantMatch:    true,
	},
	{
		name: "Match all under org ID - folder, project",
		match: map[string]interface{}{
			"ancestries": []interface{}{"organizations/123454321/**"},
		},
		ancestryPath: "organizations/123454321/folders/125896/projects/1242511",
		wantMatch:    true,
	},
	{
		name: "No match folder on descendants",
		match: map[string]interface{}{
			"ancestries": []interface{}{"**/folders/1221214/**"},
		},
		ancestryPath: "organizations/123454321/folders/1221214",
		wantMatch:    false,
	},
	{
		name: "No match folder",
		match: map[string]interface{}{
			"ancestries": []interface{}{"**/folders/1221214/**"},
		},
		ancestryPath: "organizations/123454321/folders/1221215",
		wantMatch:    false,
	},
	{
		name: "No match under folder",
		match: map[string]interface{}{
			"ancestries": []interface{}{"**/folders/1221214/**"},
		},
		ancestryPath: "organizations/123454321/folders/12212144/projects/1221214",
		wantMatch:    false,
	},
	{
		name: "Match folder in folder",
		match: map[string]interface{}{
			"ancestries": []interface{}{"**/folders/1221214/**"},
		},
		ancestryPath: "organizations/123454321/folders/1221214/folders/557385378",
		wantMatch:    true,
	},
	{
		name: "Match project in folder",
		match: map[string]interface{}{
			"ancestries": []interface{}{"**/folders/1221214/**"},
		},
		ancestryPath: "organizations/123454321/folders/1221214/projects/557385378",
		wantMatch:    true,
	},
	{
		name: "Match project",
		match: map[string]interface{}{
			"ancestries": []interface{}{"**/projects/557385378"},
		},
		ancestryPath: "organizations/123454321/folders/1221214/projects/557385378",
		wantMatch:    true,
	},
	{
		name: "Match project by ID, not number",
		match: map[string]interface{}{
			"ancestries": []interface{}{"**/projects/tfv-test-project"},
		},
		ancestryPath: "organizations/123454321/folders/1221214/projects/tfv-test-project",
		wantMatch:    true,
	},
	{
		name: "Match any project",
		match: map[string]interface{}{
			"ancestries": []interface{}{"**/projects/**"},
		},
		ancestryPath: "organizations/123454321/folders/1221214/projects/557385378",
		wantMatch:    true,
	},
	{
		name: "Does not match project",
		match: map[string]interface{}{
			"ancestries": []interface{}{"**/projects/123245"},
		},
		ancestryPath: "organizations/123454321/folders/1221214/projects/557385378",
		wantMatch:    false,
	},
	{
		name: "Match project multiple",
		match: map[string]interface{}{
			"ancestries": []interface{}{"**/projects/9795872589", "**/projects/557385378"},
		},
		ancestryPath: "organizations/123454321/folders/1221214/projects/557385378",
		wantMatch:    true,
	},
	{
		name: "Match any project",
		match: map[string]interface{}{
			"ancestries": []interface{}{"**/projects/*"},
		},
		ancestryPath: "organizations/123454321/folders/1221214/projects/557385378",
		wantMatch:    true,
	},
	{
		name: "Exclude project",
		match: map[string]interface{}{
			"excludedAncestries": []interface{}{"**/projects/557385378"},
		},
		ancestryPath: "organizations/123454321/folders/1221214/projects/557385378",
		wantMatch:    false,
	},
	{
		name: "Exclude project by ID, not number",
		match: map[string]interface{}{
			"excludedAncestries": []interface{}{"**/projects/tfv-exclude-project"},
		},
		ancestryPath: "organizations/123454321/folders/1221214/projects/tfv-exclude-project",
		wantMatch:    false,
	},
	{
		name: "Exclude project multiple",
		match: map[string]interface{}{
			"excludedAncestries": []interface{}{"**/projects/525572987", "**/projects/557385378"},
		},
		ancestryPath: "organizations/123454321/folders/1221214/projects/557385378",
		wantMatch:    false,
	},
	{
		name: "Exclude project via wildcard on org",
		match: map[string]interface{}{
			"excludedAncestries": []interface{}{"organizations/*/projects/557385378"},
		},
		ancestryPath: "organizations/123454321/projects/557385378",
		wantMatch:    false,
	},
	{
		name: "invalid target CRM type",
		match: map[string]interface{}{
			"ancestries": []interface{}{"flubber/*"},
		},
		wantConstraintError: true,
	},
	{
		name: "org after folder",
		match: map[string]interface{}{
			"ancestries": []interface{}{"folders/123/organizations/*"},
		},
		wantConstraintError: true,
	},
	{
		name: "org after project",
		match: map[string]interface{}{
			"ancestries": []interface{}{"projects/123/organizations/*"},
		},
		wantConstraintError: true,
	},
	{
		name: "folder after project",
		match: map[string]interface{}{
			"ancestries": []interface{}{"projects/123/folders/123"},
		},
		wantConstraintError: true,
	},
	{
		name: "invalid exclude CRM name",
		match: map[string]interface{}{
			"excludedAncestries": []interface{}{"foosball/*"},
		},
		wantConstraintError: true,
	},
	{
		name: "Bad target type",
		match: map[string]interface{}{
			"ancestries": "organizations/*",
		},
		wantConstraintError: true,
	},
	{
		name: "Bad target item type",
		match: map[string]interface{}{
			"ancestries": []interface{}{1},
		},
		wantConstraintError: true,
	},
	{
		name: "Bad exclude type",
		match: map[string]interface{}{
			"excludedAncestries": "organizations/*",
		},
		wantConstraintError: true,
	},
	{
		name: "Bad exclude item type",
		match: map[string]interface{}{
			"excludedAncestries": []interface{}{1},
		},
		wantConstraintError: true,
	},
}

// Tests for what happens when you try to define
// both target and ancestries or both exclude and
// excludedAncestries
var legacyMatchConflictTests = []reviewTestData{
	{
		name: "target and ancestries",
		match: map[string]interface{}{
			"ancestries": []interface{}{"organizations/123454321"},
			"target":     []interface{}{"organizations/123454321"},
		},
		wantConstraintError: true,
	},
	{
		name: "exclude and excludedAncestries",
		match: map[string]interface{}{
			"excludedAncestries": []interface{}{"organizations/123454321"},
			"exclude":            []interface{}{"organizations/123454321"},
		},
		wantConstraintError: true,
	},
}

func TestTargetHandler(t *testing.T) {
	var testcases []*targettesting.ReviewTestcase
	for _, tc := range matchTests {
		testcases = append(
			testcases,
			tc.jsonAssetTestcase(),
			tc.assetTestcase(),
			tc.legacySpecMatchTestcase(),
		)
	}

	for _, tc := range legacyMatchConflictTests {
		testcases = append(
			testcases,
			tc.jsonAssetTestcase(),
			tc.assetTestcase(),
		)
	}

	targettesting.CreateTargetHandler(t, New(), testcases).Test(t)
}
