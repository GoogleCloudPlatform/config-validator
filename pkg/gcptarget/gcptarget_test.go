package gcptarget

import (
	"fmt"
	"testing"

	"github.com/forseti-security/config-validator/pkg/api/validator"
	gcptest "github.com/forseti-security/config-validator/pkg/gcptarget/testing"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	v1 "google.golang.org/genproto/googleapis/cloud/asset/v1"
)

// match creates a match struct as would exist in a FCV constraint
func match(opts ...func(map[string]interface{})) map[string]interface{} {
	matchBlock := map[string]interface{}{}
	for _, opt := range opts {
		opt(matchBlock)
	}
	return matchBlock
}

func stringToInterface(s []string) []interface{} {
	iface := make([]interface{}, len(s))
	for i := range s {
		iface[i] = s[i]
	}
	return iface
}

// target populates the targets field inside of the match block
func target(targets ...string) func(map[string]interface{}) {
	return func(matchBlock map[string]interface{}) {
		matchBlock["target"] = stringToInterface(targets)
	}
}

// exclude populates the exclude field inside of the match block
func exclude(excludes ...string) func(map[string]interface{}) {
	return func(matchBlock map[string]interface{}) {
		matchBlock["exclude"] = stringToInterface(excludes)
	}
}

// forsetiAsset creates an FCV asset with the given ancestry path.
func forsetiAsset(ancestryPath string) func(t *testing.T) interface{} {
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

func (td *reviewTestData) assetTest(nameMod string) *gcptest.ReviewTestcase {
	tc := &gcptest.ReviewTestcase{
		Name:                nameMod + " " + td.name,
		Match:               td.match,
		WantMatch:           td.wantMatch,
		WantConstraintError: td.wantConstraintError,
	}
	if td.match != nil {
		tc.Match = td.match
	}
	return tc
}

func (td *reviewTestData) jsonAssetTestcase() *gcptest.ReviewTestcase {
	assetTest := td.assetTest("json")
	assetTest.Object = gcptest.FromJSON(fmt.Sprintf(`
{
  "name": "test-name",
  "asset_type": "test-asset-type",
  "ancestry_path": "%s",
  "resource": {}
}
`, td.ancestryPath))
	return assetTest
}

func (td *reviewTestData) forsetiAssetTestcase() *gcptest.ReviewTestcase {
	assetTest := td.assetTest("forseti")
	assetTest.Object = forsetiAsset(td.ancestryPath)
	return assetTest
}

var testData = []reviewTestData{
	{
		name:         "Null match object (matches anything)",
		ancestryPath: "organizations/123454321/folders/1221214",
		wantMatch:    true,
	},
	{
		name:         "No match specified (matches anything)",
		match:        match(),
		ancestryPath: "organizations/123454321/folders/1221214",
		wantMatch:    true,
	},
	{
		name:         "Match org on exact ID",
		match:        match(target("organizations/123454321")),
		ancestryPath: "organizations/123454321",
		wantMatch:    true,
	},
	{
		name:         "Does not match org for descendant match",
		match:        match(target("organizations/123454321/**")),
		ancestryPath: "organizations/123454321",
		wantMatch:    false,
	},
	{
		name:         "No match org on close ID",
		match:        match(target("organizations/123454321/*")),
		ancestryPath: "organizations/1234543211",
		wantMatch:    false,
	},
	{
		name:         "Match all under org ID - folder",
		match:        match(target("organizations/123454321/**")),
		ancestryPath: "organizations/123454321/folders/1242511",
		wantMatch:    true,
	},
	{
		name:         "Match all under org ID - project",
		match:        match(target("organizations/123454321/**")),
		ancestryPath: "organizations/123454321/projects/1242511",
		wantMatch:    true,
	},
	{
		name:         "Match all under org ID - folder, project",
		match:        match(target("organizations/123454321/**")),
		ancestryPath: "organizations/123454321/folders/125896/projects/1242511",
		wantMatch:    true,
	},
	{
		name:         "No match folder on descendants",
		match:        match(target("**/folders/1221214/**")),
		ancestryPath: "organizations/123454321/folders/1221214",
		wantMatch:    false,
	},
	{
		name:         "No match folder",
		match:        match(target("**/folders/1221214/**")),
		ancestryPath: "organizations/123454321/folders/1221215",
		wantMatch:    false,
	},
	{
		name:         "No match under folder",
		match:        match(target("**/folders/1221214/**")),
		ancestryPath: "organizations/123454321/folders/12212144/projects/1221214",
		wantMatch:    false,
	},
	{
		name:         "Match folder in folder",
		match:        match(target("**/folders/1221214/**")),
		ancestryPath: "organizations/123454321/folders/1221214/folders/557385378",
		wantMatch:    true,
	},
	{
		name:         "Match project in folder",
		match:        match(target("**/folders/1221214/**")),
		ancestryPath: "organizations/123454321/folders/1221214/projects/557385378",
		wantMatch:    true,
	},
	{
		name:         "Match project",
		match:        match(target("**/projects/557385378")),
		ancestryPath: "organizations/123454321/folders/1221214/projects/557385378",
		wantMatch:    true,
	},
	{
		name:         "Match any project",
		match:        match(target("**/projects/**")),
		ancestryPath: "organizations/123454321/folders/1221214/projects/557385378",
		wantMatch:    true,
	},
	{
		name:         "Does not match project",
		match:        match(target("**/projects/123245")),
		ancestryPath: "organizations/123454321/folders/1221214/projects/557385378",
		wantMatch:    false,
	},
	{
		name:         "Match project multiple",
		match:        match(target("**/projects/9795872589", "**/projects/557385378")),
		ancestryPath: "organizations/123454321/folders/1221214/projects/557385378",
		wantMatch:    true,
	},
	{
		name:         "Exclude project",
		match:        match(exclude("**/projects/557385378")),
		ancestryPath: "organizations/123454321/folders/1221214/projects/557385378",
		wantMatch:    false,
	},
	{
		name:         "Exclude project multiple",
		match:        match(exclude("**/projects/525572987", "**/projects/557385378")),
		ancestryPath: "organizations/123454321/folders/1221214/projects/557385378",
		wantMatch:    false,
	},
	{
		name:                "invalid target CRM type",
		match:               match(target("flubber/*")),
		wantConstraintError: true,
	},
	{
		name:                "org after folder",
		match:               match(target("folders/123/organizations/*")),
		wantConstraintError: true,
	},
	{
		name:                "org after project",
		match:               match(target("projects/123/organizations/*")),
		wantConstraintError: true,
	},
	{
		name:                "folder after project",
		match:               match(target("projects/123/folders/123")),
		wantConstraintError: true,
	},
	{
		name:                "invalid exclude CRM name",
		match:               match(exclude("foosball/*")),
		wantConstraintError: true,
	},
	{
		name: "Bad target type",
		match: map[string]interface{}{
			"target": "organizations/*",
		},
		wantConstraintError: true,
	},
	{
		name: "Bad target item type",
		match: map[string]interface{}{
			"target": []interface{}{1},
		},
		wantConstraintError: true,
	},
	{
		name: "Bad exclude type",
		match: map[string]interface{}{
			"exclude": "organizations/*",
		},
		wantConstraintError: true,
	},
	{
		name: "Bad exclude item type",
		match: map[string]interface{}{
			"exclude": []interface{}{1},
		},
		wantConstraintError: true,
	},
}

func TestTargetHandler(t *testing.T) {
	var targetHandlerTest = gcptest.TargetHandlerTest{
		NewTargetHandler: func(t *testing.T) client.TargetHandler {
			return New()
		},
	}

	for _, tc := range testData {
		targetHandlerTest.ReviewTestcases = append(
			targetHandlerTest.ReviewTestcases,
			tc.jsonAssetTestcase(),
			tc.forsetiAssetTestcase(),
		)
	}
	targetHandlerTest.Test(t)
}
