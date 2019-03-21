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
	"io/ioutil"
	"log"
	"sort"
	"testing"

	pb "github.com/golang/protobuf/ptypes/struct"
	"github.com/google/go-cmp/cmp"
	"partner-code.googlesource.com/gcv/gcv/pkg/api/validator"
	"partner-code.googlesource.com/gcv/gcv/pkg/gcv/configs"
)

func TestCMF_TemplateSetup(t *testing.T) {
	testCasts := []struct {
		description         string
		templates           []*configs.ConstraintTemplate
		expectTemplateError bool
	}{
		{
			description:         "no templates",
			expectTemplateError: false,
			templates:           []*configs.ConstraintTemplate{},
		},
		{
			description:         "colliding types",
			expectTemplateError: true,
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template_1"),
				makeTestTemplate("template_1"),
			},
		},
		{
			description:         "dummy helper method WAI",
			expectTemplateError: false,
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template_1"),
			},
		},
	}
	for _, tc := range testCasts {
		t.Run(tc.description, func(t *testing.T) {
			cf, err := New(getRegoDependencies())
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

			if len(errs) == 0 && tc.expectTemplateError {
				t.Errorf("want errors %v got errors %v", tc.expectTemplateError, errs)
			}
		})
	}
}

func TestCMF_ConstraintSetup(t *testing.T) {
	testCasts := []struct {
		description           string
		templates             []*configs.ConstraintTemplate
		constraints           []*configs.Constraint
		expectConstraintError bool
	}{
		{
			description:           "no templates or constraints",
			expectConstraintError: false,
			templates:             []*configs.ConstraintTemplate{},
			constraints:           []*configs.Constraint{},
		},
		{
			description:           "no constraints",
			expectConstraintError: false,
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("random_kind"),
			},
			constraints: []*configs.Constraint{},
		},
		{
			description:           "constraint kind doesn't match templates",
			expectConstraintError: true,
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("the_template_kind"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("unmatched_kind", "some_random_name", "N/A"),
			},
		},
		{
			description:           "valid colliding constraint kinds, unique metadata names",
			expectConstraintError: false,
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("the_best_kind"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("the_best_kind", "constraint_1", "N/A"),
				makeTestConstraint("the_best_kind", "constraint_2", "N/A"),
			},
		},
		{
			description:           "valid colliding constraint metadata names with unique kinds",
			expectConstraintError: false,
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
			description:           "metadata name collision",
			expectConstraintError: true,
			templates: []*configs.ConstraintTemplate{
				makeTestTemplate("template_1"),
			},
			constraints: []*configs.Constraint{
				makeTestConstraint("template_1", "colliding_name", "N/A"),
				makeTestConstraint("template_1", "colliding_name", "N/A"),
			},
		},
		{
			description:           "template without constraint",
			expectConstraintError: false,
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
			cf, err := New(getRegoDependencies())
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

			if len(errs) == 0 && tc.expectConstraintError {
				t.Errorf("want errors %v got errors %v", tc.expectConstraintError, errs)
			}
		})
	}
}

func TestCF_New_CompilerError(t *testing.T) {
	_, err := New(map[string]string{"invalid_rego": "this isn't valid rego"})
	if err == nil {
		t.Fatal("Expected error, got none")
	}
}

func TestCF_AuditParsing_WithMockAudit(t *testing.T) {
	testCases := []struct {
		description    string
		auditRego      string
		expectedResult *validator.AuditResponse
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
				Violations: []*validator.Violation{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cf, err := New(map[string]string{
				"mock_audit": tc.auditRego,
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := cf.Audit(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(sortViolations(tc.expectedResult), sortViolations(result)); diff != "" {
				t.Errorf("unexpected result (-want +got) %v", diff)
			}
		})
	}
}

func TestCF_AuditParsing_WithRealAudit(t *testing.T) {
	testCases := []struct {
		description    string
		templates      []*configs.ConstraintTemplate
		constraints    []*configs.Constraint
		data           []interface{}
		expectedResult *validator.AuditResponse
	}{
		{
			description: "everything empty",
			templates:   []*configs.ConstraintTemplate{},
			constraints: []*configs.Constraint{},
			data:        []interface{}{},
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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
			expectedResult: &validator.AuditResponse{
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

	auditCode := getRealAuditCode()

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cf, err := New(map[string]string{
				"audit": auditCode,
			})
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
			if diff := cmp.Diff(sortViolations(tc.expectedResult), sortViolations(result)); diff != "" {
				t.Errorf("unexpected result (-want +got) %v", diff)
			}
		})
	}
}

func TestCF_Audit_MalformedOutput(t *testing.T) {
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
			cf, err := New(map[string]string{
				"mock_audit": tc.auditRego,
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := cf.Audit(context.Background())
			if err == nil {
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

func getRegoDependencies() map[string]string {
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
		"name":       name,
		"asset_type": assetType,
	}
}

func makeTestConstraint(kind, metadataName string, assetType string) *configs.Constraint {
	return mustMakeConstraint(fmt.Sprintf(`
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: %s
metadata:
  name: %s
spec:
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
   validation.gcp.forsetisecurity.org:
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

func getRealAuditCode() string {
	auditFile, err := ioutil.ReadFile("../../../../policies/validator/lib/audit.rego")
	if err != nil {
		panic(err)
	}
	return string(auditFile)
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
