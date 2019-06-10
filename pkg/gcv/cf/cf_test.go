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

package cf

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"testing"

	"github.com/forseti-security/config-validator/pkg/api/validator"
	"github.com/forseti-security/config-validator/pkg/gcv/configs"
	pb "github.com/golang/protobuf/ptypes/struct"
	"github.com/google/go-cmp/cmp"
)

func TestCFTemplateSetup(t *testing.T) {
	testCasts := []struct {
		description string
		templates   []*configs.ConstraintTemplate
		wantErr     bool
	}{
		{
			description: "no templates",
			templates:   []*configs.ConstraintTemplate{},
		},
		{
			description: "colliding types",
			wantErr:     true,
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template_1"),
				makeTestTemplate("template_1"),
			},
		},
		{
			description: "dummy helper method WAI",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template_1"),
			},
		},
	}
	for _, tc := range testCasts {
		t.Run(tc.description, func(t *testing.T) {
			cf, err := New(regoDependencies())
			if err != nil {
				t.Fatal(err)
			}
			var errs []error
			for _, template := range tc.templates {
				err := cf.AddTemplate(template)
				if err != nil {
					errs = append(errs, err)
				}
			}

			if len(errs) == 0 && tc.wantErr {
				t.Errorf("want errors %v got errors %v", tc.wantErr, errs)
			}
		})
	}
}

func TestCFTemplateDependencyCodeCollision(t *testing.T) {
	// The rego compiler takes a single map[string]string as input to compile, but there are 2 maps
	// saved in the config validator.
	// One for the dependency code (this map is provided as input to cf. So cf doesn't control the map keys)
	// and one for the templates (cf creates this map so has full control over the map keys).
	//
	// These map's have to be combined for the rego compiler, but they shouldn't have collisions on
	// their keys.
	//
	// Attempt to make a key collision by using `templatePkgPath` (which is used in the map key for
	// templates) when providing a user specified rego dependency

	// Currently (Mar 2019): the dependency code is intended to be deprecated when template's inline
	// any rego libraries. Once that happens this shouldn't be a concern any more.
	template := makeTestTemplate("someKind")
	randomRegoCode := makeTestTemplate("someOtherKind").Rego
	cf, err := New(map[string]string{
		templatePkgPath(template): randomRegoCode,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = cf.AddTemplate(template)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := cf.compile()
	if err != nil {
		t.Fatal(err)
	}
	wantModuleCount := 3 // audit + dependency code + template
	if len(compiler.Modules) != wantModuleCount {
		t.Fatalf("unexpected number of compiled modules: got %d want %d", len(compiler.Modules), wantModuleCount)
	}
}

func TestCFConstraintSetup(t *testing.T) {
	testCasts := []struct {
		description string
		templates   []*configs.ConstraintTemplate
		constraints []*configs.Constraint
		wantErr     bool
	}{
		{
			description: "no templates or constraints",
			templates:   []*configs.ConstraintTemplate{},
			constraints: []*configs.Constraint{},
		},
		{
			description: "no constraints",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("random_kind"),
			},
			constraints: []*configs.Constraint{},
		},
		{
			description: "constraint kind doesn't match templates",
			wantErr:     true,
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("the_template_kind"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("unmatched_kind", "some_random_name", "N/A"),
			},
		},
		{
			description: "valid colliding constraint kinds, unique metadata names",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("the_best_kind"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("the_best_kind", "constraint_1", "N/A"),
				makeTestConstraint("the_best_kind", "constraint_2", "N/A"),
			},
		},
		{
			description: "valid colliding constraint metadata names with unique kinds",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template_1"),
				makeTestTemplate("template_2"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template_1", "colliding_name", "N/A"),
				makeTestConstraint("template_2", "colliding_name", "N/A"),
			},
		},
		{
			description: "metadata name collision",
			wantErr:     true,
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template_1"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template_1", "colliding_name", "N/A"),
				makeTestConstraint("template_1", "colliding_name", "N/A"),
			},
		},
		{
			description: "template without constraint",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template_1"),
				makeTestTemplate("UNMATCHED_template"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template_1", "colliding_name", "N/A"),
			},
		},
	}
	for _, tc := range testCasts {
		t.Run(tc.description, func(t *testing.T) {
			cf, err := New(regoDependencies())
			if err != nil {
				t.Fatal(err)
			}
			for _, template := range tc.templates {
				err := cf.AddTemplate(template)
				if err != nil {
					t.Error("unexpected error adding template: ", err)
				}
			}
			var errs []error
			for _, constraint := range tc.constraints {
				err := cf.AddConstraint(constraint)
				if err != nil {
					errs = append(errs, err)
				}
			}

			if len(errs) == 0 && tc.wantErr {
				t.Errorf("want errors %v got errors %v", tc.wantErr, errs)
			}
		})
	}
}

func TestCFNewCompilerError(t *testing.T) {
	_, err := New(map[string]string{"invalid_rego": "this isn't valid rego"})
	if err == nil {
		t.Fatal("Expected error, got none")
	}
}

func TestCFAuditParsingWithMockAudit(t *testing.T) {
	testCases := []struct {
		description string
		auditRego   string
		want        *validator.AuditResponse
	}{
		{
			description: "no  metadata",
			auditRego: `package validator.gcp.lib
audit[result] {
  result := {
    "constraint": "example_constraint_metadata_name_name",
    "asset": "some_asset_name",
    "violation": {
      "msg": "tmp example issue",
    }
  }
}
`,
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{
					{
						Constraint: "example_constraint_metadata_name_name",
						Resource:   "some_asset_name",
						Message:    "tmp example issue",
					},
				},
			},
		},
		{
			description: "empty metadata",
			auditRego: `package validator.gcp.lib
audit[result] {
  result := {
    "constraint": "example_constraint_metadata_name_name",
    "asset": "some_asset_name",
    "violation": {
      "msg": "tmp example issue",
      "details": {}
    }
  }
}
`,
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{
					{
						Constraint: "example_constraint_metadata_name_name",
						Resource:   "some_asset_name",
						Message:    "tmp example issue",
						Metadata:   mustConvertToProtoVal(struct{}{}),
					},
				},
			},
		},
		{
			description: "Single level metadata",
			auditRego: `package validator.gcp.lib
audit[result] {
  result := {
    "constraint": "example_constraint_metadata_name_name",
    "asset": "some_asset_name",
    "violation": {"msg":"tmp example issue", "details": {"some":"random","things":"4u"}}
  }
}
`,
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{
					{
						Constraint: "example_constraint_metadata_name_name",
						Resource:   "some_asset_name",
						Message:    "tmp example issue",
						Metadata: mustConvertToProtoVal(map[string]interface{}{
							"some":   "random",
							"things": "4u",
						}),
					},
				},
			},
		},
		{
			description: "multilevel nested metadata",
			auditRego: `package validator.gcp.lib
audit[result] {
  result := {
    "constraint": "example_constraint_metadata_name_name",
    "asset": "some_asset_name",
    "violation": {"msg":"tmp example issue", "details": {"some":{"really":"random"},"things":"4u"}}
  }
}
`,
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{
					{
						Constraint: "example_constraint_metadata_name_name",
						Resource:   "some_asset_name",
						Message:    "tmp example issue",
						Metadata: mustConvertToProtoVal(map[string]interface{}{
							"some": map[string]interface{}{
								"really": "random",
							},
							"things": "4u",
						}),
					},
				},
			},
		},
		{
			description: "Multiple results",
			auditRego: `package validator.gcp.lib
audit[result] {
  examples = ["example_1","example_2"]
  example := examples[_]

  result := {
    "constraint": example,
    "asset": "some_asset_name",
    "violation": {
      "msg": "tmp example issue",
    }
  }
}
`,
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{
					{
						Constraint: "example_1",
						Resource:   "some_asset_name",
						Message:    "tmp example issue",
					},
					{
						Constraint: "example_2",
						Resource:   "some_asset_name",
						Message:    "tmp example issue",
					},
				},
			},
		},
		{
			description: "no audit errors",
			auditRego: `package validator.gcp.lib
audit[result] {
  examples = []
  example := examples[_]

  result := {
    "asset": example,
    "asset": "some_asset_name",
    "violation": {
      "msg": "tmp example issue",
    }
  }
}
`,
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cf, err := New(map[string]string{})
			if err != nil {
				t.Fatal(err)
			}
			cf.auditScript = tc.auditRego
			result, err := cf.Audit(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(sortViolations(tc.want), sortViolations(result)); diff != "" {
				t.Errorf("unexpected result (-want +got) %v", diff)
			}
		})
	}
}

func TestCFAuditParsingWithRealAudit(t *testing.T) {
	testCases := []struct {
		description string
		templates   []*configs.ConstraintTemplate
		constraints []*configs.Constraint
		data        []interface{}
		want        *validator.AuditResponse
	}{
		{
			description: "everything empty",
			templates:   []*configs.ConstraintTemplate{},
			constraints: []*configs.Constraint{},
			data:        []interface{}{},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{},
			},
		},
		{
			description: "no templates or constraints with data",
			templates:   []*configs.ConstraintTemplate{},
			constraints: []*configs.Constraint{},
			data: []interface{}{
				makeTestData("nothing really", "matters"),
			},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{},
			},
		},
		{
			description: "no constraints with template/data",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("ignored"),
			},
			constraints: []*configs.Constraint{}, // no constraints, so nothing evaluated
			data: []interface{}{
				makeTestData("nothing really", "matters"),
			},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{},
			},
		},
		{
			description: "single template/constraint/data pass",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template", "constraint", "legit"),
			},
			data: []interface{}{
				makeTestData("my_data", "legit"),
			},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{},
			},
		},
		{
			description: "single template/constraint/data fail",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template", "constraint", "legit"),
			},
			data: []interface{}{
				makeTestData("my_data", "invalid"),
			},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{
					{
						Constraint: "constraint",
						Resource:   "my_data",
						Message:    "it broke!",
					},
				},
			},
		},
		{
			description: "single template/constraint multiple data pass",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template", "constraint", "legit"),
			},
			data: []interface{}{
				makeTestData("my_data_1", "legit"),
				makeTestData("my_data_2", "legit"),
			},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{},
			},
		},
		{
			description: "single template/constraint multiple data mix pass/fail",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template", "constraint", "legit"),
			},
			data: []interface{}{
				makeTestData("my_data_1", "legit"),
				makeTestData("my_data_2", "invalid"),
			},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{
					{
						Constraint: "constraint",
						Resource:   "my_data_2",
						Message:    "it broke!",
					},
				},
			},
		},
		{
			description: "single template/constraint multiple data fail",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template", "constraint", "legit"),
			},
			data: []interface{}{
				makeTestData("my_data_1", "invalid"),
				makeTestData("my_data_2", "invalid"),
			},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{
					{
						Constraint: "constraint",
						Resource:   "my_data_1",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint",
						Resource:   "my_data_2",
						Message:    "it broke!",
					},
				},
			},
		},
		{
			description: "single template multiple constraint/data pass",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template", "constraint", "legit"),
				makeTestConstraint("template", "constraint_2", "legit"),
			},
			data: []interface{}{
				makeTestData("my_data_1", "legit"),
				makeTestData("my_data_2", "legit"),
			},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{},
			},
		},
		{
			description: "single template/data multiple constraints, mix pass/fail",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template", "constraint_pass", "legit"),
				makeTestConstraint("template", "constraint_fail", "dont_match"),
			},
			data: []interface{}{
				makeTestData("my_asset", "legit"),
			},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{
					{
						Constraint: "constraint_fail",
						Resource:   "my_asset",
						Message:    "it broke!",
					},
				},
			},
		},
		{
			description: "single template/data multiple constraints, all fail",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template", "constraint_fail_1", "fail_2_match"),
				makeTestConstraint("template", "constraint_fail_2", "fail_3_match"),
			},
			data: []interface{}{
				makeTestData("my_asset", "legit"),
			},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{
					{
						Constraint: "constraint_fail_1",
						Resource:   "my_asset",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint_fail_2",
						Resource:   "my_asset",
						Message:    "it broke!",
					},
				},
			},
		},
		{
			description: "single template multiple constraints/data, mix pass/fail",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template", "constraint_1", "pass_1"),
				makeTestConstraint("template", "constraint_2", "pass_2"),
			},
			data: []interface{}{
				makeTestData("my_asset_1", "pass_1"),
				makeTestData("my_asset_2", "pass_2"),
			},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{
					{
						Constraint: "constraint_2",
						Resource:   "my_asset_1",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint_1",
						Resource:   "my_asset_2",
						Message:    "it broke!",
					},
				},
			},
		},
		{
			description: "single template multiple constraints/data, all fail",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template", "constraint_1", "pass_1"),
				makeTestConstraint("template", "constraint_2", "pass_2"),
			},
			data: []interface{}{
				makeTestData("my_asset_1", "invalid"),
				makeTestData("my_asset_2", "invalid"),
			},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{
					{
						Constraint: "constraint_1",
						Resource:   "my_asset_1",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint_2",
						Resource:   "my_asset_1",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint_1",
						Resource:   "my_asset_2",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint_2",
						Resource:   "my_asset_2",
						Message:    "it broke!",
					},
				},
			},
		},
		{
			description: "multiple template/constraint/data pass",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template_1"),
				makeTestTemplate("template_2"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template_1", "constraint", "legit"),
				makeTestConstraint("template_1", "constraint_2", "legit"),
				makeTestConstraint("template_2", "constraint", "legit"),
				makeTestConstraint("template_2", "constraint_2", "legit"),
			},
			data: []interface{}{
				makeTestData("my_data_1", "legit"),
				makeTestData("my_data_2", "legit"),
			},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{},
			},
		},
		{
			description: "multiple template/constraint/data mix pass/fail",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template_1"),
				makeTestTemplate("template_2"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template_1", "constraint_a1", "legit"),
				makeTestConstraint("template_1", "constraint_a2", "legit"),
				makeTestConstraint("template_2", "constraint_b1", "failure"),
				makeTestConstraint("template_2", "constraint_b2", "failure"),
			},
			data: []interface{}{
				makeTestData("my_data_1", "legit"),
				makeTestData("my_data_2", "legit"),
			},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{
					{
						Constraint: "constraint_b1",
						Resource:   "my_data_1",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint_b2",
						Resource:   "my_data_1",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint_b1",
						Resource:   "my_data_2",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint_b2",
						Resource:   "my_data_2",
						Message:    "it broke!",
					},
				},
			},
		},
		{
			description: "multiple template/constraint/data all fail",
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template_1"),
				makeTestTemplate("template_2"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template_1", "constraint_a1", "failure"),
				makeTestConstraint("template_1", "constraint_a2", "failure"),
				makeTestConstraint("template_2", "constraint_b1", "failure"),
				makeTestConstraint("template_2", "constraint_b2", "failure"),
			},
			data: []interface{}{
				makeTestData("my_data_1", "sad_face"),
				makeTestData("my_data_2", "sad_face"),
			},
			want: &validator.AuditResponse{
				Violations: []*validator.Violation{
					{
						Constraint: "constraint_a1",
						Resource:   "my_data_1",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint_a2",
						Resource:   "my_data_1",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint_b1",
						Resource:   "my_data_1",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint_b2",
						Resource:   "my_data_1",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint_a1",
						Resource:   "my_data_2",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint_a2",
						Resource:   "my_data_2",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint_b1",
						Resource:   "my_data_2",
						Message:    "it broke!",
					},
					{
						Constraint: "constraint_b2",
						Resource:   "my_data_2",
						Message:    "it broke!",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cf, err := New(map[string]string{})
			if err != nil {
				t.Fatal(err)
			}
			for _, template := range tc.templates {
				err = cf.AddTemplate(template)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, constraint := range tc.constraints {
				err = cf.AddConstraint(constraint)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, data := range tc.data {
				cf.AddData(data)
			}
			result, err := cf.Audit(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(sortViolations(tc.want), sortViolations(result)); diff != "" {
				t.Errorf("unexpected result (-want +got) %v", diff)
			}
		})
	}
}
func TestTargetAndExclude(t *testing.T) {
	testCases := []struct {
		description    string
		target         []string
		exclude        []string
		ancestryPath   string
		wantMatch      bool
		withGCPWrapper bool
	}{
		{
			description:    "org wildcard (GCP wrapper)",
			target:         []string{"organization/*"},
			ancestryPath:   "organization/1/folder/2/project/3",
			wantMatch:      true,
			withGCPWrapper: true,
		},
		{
			description:  "org wildcard",
			target:       []string{"organization/*"},
			ancestryPath: "organization/1/folder/2/project/3",
			wantMatch:    true,
		},
		{
			description:    "org match (GCP wrapper)",
			target:         []string{"organization/1"},
			ancestryPath:   "organization/1/folder/2/project/3",
			wantMatch:      true,
			withGCPWrapper: true,
		},
		{
			description:  "org match",
			target:       []string{"organization/1"},
			ancestryPath: "organization/1/folder/2/project/3",
			wantMatch:    true,
		},
		{
			description:    "org mismatch (GCP wrapper)",
			target:         []string{"organization/1001"},
			ancestryPath:   "organization/1/folder/2/project/3",
			wantMatch:      false,
			withGCPWrapper: true,
		},
		{
			description:  "org mismatch",
			target:       []string{"organization/1001"},
			ancestryPath: "organization/1/folder/2/project/3",
			wantMatch:    false,
		},
		{
			description:    "folder wildcard (GCP wrapper)",
			target:         []string{"organization/1/folder/*"},
			ancestryPath:   "organization/1/folder/2/project/3",
			wantMatch:      true,
			withGCPWrapper: true,
		},
		{
			description:  "folder wildcard",
			target:       []string{"organization/1/folder/*"},
			ancestryPath: "organization/1/folder/2/project/3",
			wantMatch:    true,
		},
		{
			description:    "folder match (GCP wrapper)",
			target:         []string{"organization/1/folder/2"},
			ancestryPath:   "organization/1/folder/2/project/3",
			wantMatch:      true,
			withGCPWrapper: true,
		},
		{
			description:  "folder match",
			target:       []string{"organization/1/folder/2"},
			ancestryPath: "organization/1/folder/2/project/3",
			wantMatch:    true,
		},
		{
			description:    "folder mismatch (GCP wrapper)",
			target:         []string{"organization/1/folder/1001"},
			ancestryPath:   "organization/1/folder/2/project/3",
			wantMatch:      false,
			withGCPWrapper: true,
		},
		{
			description:  "folder mismatch",
			target:       []string{"organization/1/folder/1001"},
			ancestryPath: "organization/1/folder/2/project/3",
			wantMatch:    false,
		},
		{
			description:    "project wildcard (GCP wrapper)",
			target:         []string{"organization/1/folder/2/project/*"},
			ancestryPath:   "organization/1/folder/2/project3",
			wantMatch:      true,
			withGCPWrapper: true,
		},
		{
			description:  "project wildcard",
			target:       []string{"organization/1/folder/2/project/*"},
			ancestryPath: "organization/1/folder/2/project3",
			wantMatch:    true,
		},
		{
			description:    "project match (GCP wrapper)",
			target:         []string{"organization/1/folder/2/project/3"},
			ancestryPath:   "organization/1/folder/2/project/3",
			wantMatch:      true,
			withGCPWrapper: true,
		},
		{
			description:  "project match",
			target:       []string{"organization/1/folder/2/project/3"},
			ancestryPath: "organization/1/folder/2/project/3",
			wantMatch:    true,
		},
		{
			description:    "project mismatch (GCP wrapper)",
			target:         []string{"organization/1/folder/2/project/1001"},
			ancestryPath:   "organization/1/folder/2/project/3",
			wantMatch:      false,
			withGCPWrapper: true,
		},
		{
			description:  "project mismatch",
			target:       []string{"organization/1/folder/2/project/1001"},
			ancestryPath: "organization/1/folder/2/project/3",
			wantMatch:    false,
		},
		{
			description: "multiple targets (GCP wrapper)",
			target: []string{
				"organization/1001/folder/2/project/3",
				"organization/1/folder/1001/project/3",
				"organization/1/folder/2/project/3"},
			ancestryPath:   "organization/1/folder/2/project/3",
			wantMatch:      true,
			withGCPWrapper: true,
		},
		{
			description: "multiple targets",
			target: []string{
				"organization/1001/folder/2/project/3",
				"organization/1/folder/1001/project/3",
				"organization/1/folder/2/project/3"},
			ancestryPath: "organization/1/folder/2/project/3",
			wantMatch:    true,
		},
		{
			description:    "exclude takes precedence (GCP wrapper)",
			target:         []string{"organization/*"},
			exclude:        []string{"organization/1/folder/2"},
			ancestryPath:   "organization/1/folder/2/project/3",
			wantMatch:      false,
			withGCPWrapper: true,
		},
		{
			description:  "exclude takes precedence",
			target:       []string{"organization/*"},
			exclude:      []string{"organization/1/folder/2"},
			ancestryPath: "organization/1/folder/2/project/3",
			wantMatch:    false,
		},
		{
			description:    "multiple excludes (GCP wrapper)",
			target:         []string{"organization/1"},
			exclude:        []string{"organization/2", "organization/1/folder/2"},
			ancestryPath:   "organization/1/folder/2/project/3",
			wantMatch:      false,
			withGCPWrapper: true,
		},
		{
			description:  "multiple excludes",
			target:       []string{"organization/1"},
			exclude:      []string{"organization/2", "organization/1/folder/2"},
			ancestryPath: "organization/1/folder/2/project/3",
			wantMatch:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cf, err := New(map[string]string{})
			if err != nil {
				t.Fatal(err)
			}
			err = cf.AddTemplate(makeTestTemplate("template"))
			if err != nil {
				t.Fatal(err)
			}
			c := constraintWithTargetAndExclude(tc.withGCPWrapper, tc.target, tc.exclude)
			err = cf.AddConstraint(mustMakeConstraint(c))
			if err != nil {
				t.Fatal(err)
			}
			cf.AddData(map[string]interface{}{
				"name":          "data",
				"asset_type":    "does_not_match",
				"ancestry_path": tc.ancestryPath,
			})
			result, err := cf.Audit(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			// The constraint is guaranteed to violate because the asset type mismatch.
			// Therefore if it's missing, it means that the target mechanism excluded it.
			gotMatch := len(result.GetViolations()) > 0
			if tc.wantMatch != gotMatch {
				t.Errorf("want match: %t; got match: %t", tc.wantMatch, gotMatch)
			}
		})
	}
}

func constraintWithTargetAndExclude(withGCPWrapper bool, target, exclude []string) string {
	if withGCPWrapper {
		return fmt.Sprintf(`
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: template
metadata:
  name: "constraint"
spec:
  match:
    gcp:
      target: [%s]
      exclude: [%s]
  parameters:
    asset_type_to_check: ""`,
			strings.Join(target, ","), strings.Join(exclude, ","))
	} else {
		return fmt.Sprintf(`
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: template
metadata:
  name: "constraint"
spec:
  match:
    target: [%s]
    exclude: [%s]
  parameters:
    asset_type_to_check: ""`,
			strings.Join(target, ","), strings.Join(exclude, ","))
	}
}

func TestDefaultMatcher(t *testing.T) {
	testCases := []struct {
		description    string
		exclude        []string
		ancestryPath   string
		wantMatch      bool
		withGCPWrapper bool
	}{
		{
			description:    "default matches org (GCP wrapper)",
			ancestryPath:   "organization/1",
			wantMatch:      true,
			withGCPWrapper: true,
		},
		{
			description:  "default matches org",
			ancestryPath: "organization/1",
			wantMatch:    true,
		},
		{
			description:    "default matches folder (GCP wrapper)",
			ancestryPath:   "organization/1/folder/2",
			wantMatch:      true,
			withGCPWrapper: true,
		},
		{
			description:  "default matches folder",
			ancestryPath: "organization/1/folder/2",
			wantMatch:    true,
		},
		{
			description:    "default matches project (GCP wrapper)",
			ancestryPath:   "organization/1/folder/2/project/3",
			wantMatch:      true,
			withGCPWrapper: true,
		},
		{
			description:  "default matches project",
			ancestryPath: "organization/1/folder/2/project/3",
			wantMatch:    true,
		},
		{
			description:    "exclude works with default (GCP wrapper)",
			exclude:        []string{"organization/1/folder/2"},
			ancestryPath:   "organization/1/folder/2/project/3",
			wantMatch:      false,
			withGCPWrapper: true,
		},
		{
			description:  "exclude works with default",
			exclude:      []string{"organization/1/folder/2"},
			ancestryPath: "organization/1/folder/2/project/3",
			wantMatch:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cf, err := New(map[string]string{})
			if err != nil {
				t.Fatal(err)
			}
			if err = cf.AddTemplate(makeTestTemplate("template")); err != nil {
				t.Fatal(err)
			}
			c := constraintWithExclude(tc.withGCPWrapper, tc.exclude)
			if err = cf.AddConstraint(mustMakeConstraint(c)); err != nil {
				t.Fatal(err)
			}
			cf.AddData(map[string]interface{}{
				"name":          "data",
				"asset_type":    "does_not_match",
				"ancestry_path": tc.ancestryPath,
			})
			result, err := cf.Audit(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			// The constraint is guaranteed to violate because the asset type mismatch.
			// Therefore if it's missing, it means that the target mechanism excluded it.
			gotMatch := len(result.GetViolations()) > 0
			if tc.wantMatch != gotMatch {
				t.Errorf("want match: %t; got match: %t", tc.wantMatch, gotMatch)
			}
		})
	}
}

func constraintWithExclude(gcpWrapper bool, exclude []string) string {
	if gcpWrapper {
		return fmt.Sprintf(`
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: template
metadata:
  name: "constraint"
spec:
  match:
    gcp:
      exclude: [%s]
  parameters:
    asset_type_to_check: ""`, strings.Join(exclude, ","))
	} else {
		return fmt.Sprintf(`
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: template
metadata:
  name: "constraint"
spec:
  match:
    exclude: [%s]
  parameters:
    asset_type_to_check: ""`, strings.Join(exclude, ","))
	}
}

func TestCFAuditMalformedOutput(t *testing.T) {
	testCases := []struct {
		description string
		auditRego   string
	}{
		{
			description: "missing constraint field",
			auditRego: `package validator.gcp.lib
audit[result] {
  result := {
    "NOT_constraint": "example_constraint_metadata_name_name",
    "asset": "some_asset_name",
    "violation": {
      "msg": "tmp example issue",
    }
  }
}
`,
		},
		{
			description: "missing asset field",
			auditRego: `package validator.gcp.lib
audit[result] {
  result := {
    "constraint": "example_constraint_metadata_name_name",
    "NOT_asset": "some_asset_name",
    "violation": {
      "msg": "tmp example issue",
    }
  }
}
`,
		},
		{
			description: "missing violation field",
			auditRego: `package validator.gcp.lib
audit[result] {
  result := {
    "constraint": "example_constraint_metadata_name_name",
    "asset": "some_asset_name",
    "NOT_violation": "missing field",
  }
}
`,
		},
		{
			description: "missing audit func",
			auditRego: `package validator.gcp.lib
NOT_audit[result] {
  result := {
    "constraint": "example_constraint_metadata_name_name",
    "asset": "some_asset_name",
    "violation": {
      "msg": "tmp example issue",
    }
  }
}
`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cf, err := New(map[string]string{})
			if err != nil {
				t.Fatal(err)
			}
			cf.auditScript = tc.auditRego
			if result, err := cf.Audit(context.Background()); err == nil {
				t.Fatalf("error expected, but non thrown, instead provided result %v", result)
			}
		})
	}
}

func sortViolations(in *validator.AuditResponse) *validator.AuditResponse {
	if in == nil {
		return in
	}
	sort.Slice(in.Violations, func(i, j int) bool {
		return in.Violations[i].String() < in.Violations[j].String()
	})
	return in
}

func regoDependencies() map[string]string {
	return map[string]string{}
}

func mustConvertToProtoVal(from interface{}) *pb.Value {
	converted, err := convertToProtoVal(from)
	if err != nil {
		panic(err)
	}
	return converted
}

func makeTestData(name string, assetType string) interface{} {
	return map[string]interface{}{
		"name":          name,
		"asset_type":    assetType,
		"ancestry_path": "organization/1/folder/2/project/3",
	}
}

func makeTestConstraint(kind, metadataName, assetType string) *configs.Constraint {
	return mustMakeConstraint(fmt.Sprintf(`
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: %s
metadata:
  name: %s
spec:
  match:    
    target: ["organization/*"]
  parameters:
    asset_type_to_check: "%s"
`, kind, metadataName, assetType))
}

func makeTestTemplate(kind string) *configs.ConstraintTemplate {
	return mustMakeTemplate(fmt.Sprintf(`
apiVersion: templates.gatekeeper.sh/v1alpha1
kind: ConstraintTemplate
metadata:
  name: my-really-cool-test-template
spec:
  crd:
    spec:
      names:
        kind: %s
  targets:
    - target: validation.gcp.forsetisecurity.org
      rego: |
            package templates.gcp.%s

            deny[{
            	"msg": message,
            }] {
                asset := input.asset
                params := input.constraint.spec.parameters
                asset.asset_type != params.asset_type_to_check

                message := "it broke!"
            }
            #ENDINLINE
`, kind, kind))
}

// mustMakeConstraint compiles a constraint or panics.
func mustMakeConstraint(data string) *configs.Constraint {
	constraint, err := configs.CategorizeYAMLFile([]byte(data), "generated_by_tests")
	if err != nil {
		log.Fatal(err)
	}
	return constraint.(*configs.Constraint)
}

// mustMakeTemplate compiles a template or panics.
func mustMakeTemplate(data string) *configs.ConstraintTemplate {
	constraint, err := configs.CategorizeYAMLFile([]byte(data), "generated_by_tests")
	if err != nil {
		log.Fatal(err)
	}
	return constraint.(*configs.ConstraintTemplate)
}
