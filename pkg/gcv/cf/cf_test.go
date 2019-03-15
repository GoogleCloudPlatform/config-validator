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
	"fmt"
	"log"
	"testing"

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
			cf, err := New(getRegoDepdencies())
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
			cf, err := New(getRegoDepdencies())
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
   admission.kubernetes.gatekeeper.sh:
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

func getRegoDepdencies() map[string]string {
	return map[string]string{}
}
