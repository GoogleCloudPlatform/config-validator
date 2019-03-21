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
	"testing"

	pb "github.com/golang/protobuf/ptypes/struct"
	"github.com/google/go-cmp/cmp"
	"partner-code.googlesource.com/gcv/gcv/pkg/api/validator"
	"partner-code.googlesource.com/gcv/gcv/pkg/gcv/configs"
)

// TODO(corb): tests
//  Errors
// 	Load in single template/constrant/data and test
//    pass
//    fail
//    invalid data
//    excluded data
// 	Load in single template/constrant and multiple data and test
//    all pass
//    all fail
//    mix pass fail
//    partial invalid data
//    partial excluded data
//    all excluded data
//  Single Template, multiple constraints
//    Single data pass all
//    Single data fail all
//    Single data partial pass/fail
//    multiple data pass/fail mix for each constraint
//    multiple data partial exclude for each constraint
//  Multiple Template
//    Same as single template, but each template will have one constraint

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
				makeDummyTemplate("template_1"),
				makeDummyTemplate("template_1"),
			},
		},
		{
			description:         "dummy helper method WAI",
			expectTemplateError: false,
			templates: []*configs.ConstraintTemplate{
				makeDummyTemplate("template_1"),
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
				makeDummyTemplate("random_kind"),
			},
			constraints: []*configs.Constraint{},
		},
		{
			description:           "constraint kind doesn't match templates",
			expectConstraintError: true,
			templates: []*configs.ConstraintTemplate{
				makeDummyTemplate("the_template_kind"),
			},
			constraints: []*configs.Constraint{
				makeDummyConstraint("unmatched_kind", "some_random_name"),
			},
		},
		{
			description:           "valid colliding constraint kinds, unique metadata names",
			expectConstraintError: false,
			templates: []*configs.ConstraintTemplate{
				makeDummyTemplate("the_best_kind"),
			},
			constraints: []*configs.Constraint{
				makeDummyConstraint("the_best_kind", "constraint_1"),
				makeDummyConstraint("the_best_kind", "constraint_2"),
			},
		},
		{
			description:           "valid colliding constraint metadata names with unique kinds",
			expectConstraintError: false,
			templates: []*configs.ConstraintTemplate{
				makeDummyTemplate("template_1"),
				makeDummyTemplate("template_2"),
			},
			constraints: []*configs.Constraint{
				makeDummyConstraint("template_1", "colliding_name"),
				makeDummyConstraint("template_2", "colliding_name"),
			},
		},
		{
			description:           "metadata name collision",
			expectConstraintError: true,
			templates: []*configs.ConstraintTemplate{
				makeDummyTemplate("template_1"),
			},
			constraints: []*configs.Constraint{
				makeDummyConstraint("template_1", "colliding_name"),
				makeDummyConstraint("template_1", "colliding_name"),
			},
		},
		{
			description:           "template without constraint",
			expectConstraintError: false,
			templates: []*configs.ConstraintTemplate{
				makeDummyTemplate("template_1"),
				makeDummyTemplate("UNMATCHED_template"),
			},
			constraints: []*configs.Constraint{
				makeDummyConstraint("template_1", "colliding_name"),
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
			if diff := cmp.Diff(tc.expectedResult, result); diff != "" {
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

func makeDummyConstraint(kind, metadataName string) *configs.Constraint {
	return makeConstraint(fmt.Sprintf(`apiVersion: constraints.gatekeeper.sh/v1
kind: %s
metadata:
  name: %s
`, kind, metadataName))
}

// Compile a constraint or panic.
func makeConstraint(data string) *configs.Constraint {
	constraint, err := configs.CategorizeYAMLFile([]byte(data), "generated_by_tests")
	if err != nil {
		log.Fatal(err)
	}
	return constraint.(*configs.Constraint)
}

func makeDummyTemplate(generatedKind string) *configs.ConstraintTemplate {
	t := makeTemplate(fmt.Sprintf(`apiVersion: gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: really_cool_template_metadata_name
spec:
  crd:
    spec:
      names:
        kind: %s # name inserted here
  targets:
   validation.gcp.forsetisecurity.org:
      rego: |
            # Some random
            # rego code`, generatedKind))
	return t
}

// Compile a template or panic.
func makeTemplate(data string) *configs.ConstraintTemplate {
	constraint, err := configs.CategorizeYAMLFile([]byte(data), "generated_by_tests")
	if err != nil {
		log.Fatal(err)
	}
	return constraint.(*configs.ConstraintTemplate)
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
