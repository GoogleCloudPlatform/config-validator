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

package oldconfigs

import (
	"log"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/smallfish/simpleyaml"
)

func TestCategorizeYAMLFile(t *testing.T) {
	testCases := []struct {
		description string
		data        string
		expected    interface{}
		wantErr     bool
	}{
		{
			description: "empty file",
			data:        "",
			wantErr:     true,
		},
		{
			description: "invalid yaml",
			data:        "dis ain't yaml!",
			wantErr:     true,
		},
		{
			description: "invalid template kind",
			data: `apiVersion: templates.gatekeeper.sh/v1alpha1
kind: INCORRECT_KIND  # Error here
metadata:
  name: really_cool_template_metadata_name
spec:
  crd:
    spec:
      names:
        kind: GCPExternalIpAccessConstraint
  targets:
    - target: validation.gcp.forsetisecurity.org
      rego: |
            # Some random
            # rego code
`,
			wantErr: true,
		},
		{
			description: "invalid template api version",
			data: `apiVersion: INVALID_API_VERSION  # Error here
kind: ConstraintTemplate
metadata:
  name: really_cool_template_metadata_name
spec:
  crd:
    spec:
      names:
        kind: GCPExternalIpAccessConstraint
  targets:
    - target: validation.gcp.forsetisecurity.org
      rego: |
            # Some random
            # rego code
`,
			wantErr: true,
		},
		{
			description: "invalid template api version (using constraint kind)",
			data: `apiVersion: constraints.gatekeeper.sh/v1alpha1  # Error here
kind: ConstraintTemplate
metadata:
  name: really_cool_template_metadata_name
spec:
  crd:
    spec:
      names:
        kind: GCPExternalIpAccessConstraint
  targets:
    - target: validation.gcp.forsetisecurity.org
      rego: |
            # Some random
            # rego code
`,
			wantErr: true,
		},
		{
			description: "invalid template invalid target",
			data: `apiVersion: templates.gatekeeper.sh/v1alpha1
kind: ConstraintTemplate
metadata:
  name: really_cool_template_metadata_name
spec:
  crd:
    spec:
      names:
        kind: GCPExternalIpAccessConstraint
  targets:
    This_is_the_wrong_field:
      rego: |
            # Some random
            # rego code
`,
			wantErr: true,
		},
		{
			description: "invalid template no generated kind",
			data: `apiVersion: templates.gatekeeper.sh/v1alpha1
kind: ConstraintTemplate
metadata:
  name: really_cool_template_metadata_name
spec:
  crd:
    spec:
      names:
        kind_doesnt_exist': GCPExternalIpAccessConstraint # Error here
  targets:
    - target: validation.gcp.forsetisecurity.org
      rego: |
            # Some random
            # rego code
`,
			wantErr: true,
		},
		{
			description: "legacy template without target list",
			data: `apiVersion: templates.gatekeeper.sh/v1alpha1
kind: ConstraintTemplate  # Confirm comments WAI
metadata:
  name: really_cool_template_metadata_name
spec:
  crd:
    spec:
      names:
        kind: GCPExternalIpAccessConstraint
  targets:
    validation.gcp.forsetisecurity.org:
      rego: |
            # Some random
            # rego code
`,
			expected: &ConstraintTemplate{
				GeneratedKind: "GCPExternalIpAccessConstraint",
				Rego: `# Some random
# rego code
`,
				Confg: UnclassifiedConstraintBuilder(&UnclassifiedConfig{
					Group:        "templates.gatekeeper.sh/v1alpha1",
					MetadataName: "really_cool_template_metadata_name",
					Kind:         "ConstraintTemplate",
					FilePath:     "legacy template without target list", // will be a copy of the description
				}, `apiVersion: templates.gatekeeper.sh/v1alpha1
kind: ConstraintTemplate  # Confirm comments WAI
metadata:
  name: really_cool_template_metadata_name
spec:
  crd:
    spec:
      names:
        kind: GCPExternalIpAccessConstraint
  targets:
    validation.gcp.forsetisecurity.org:
      rego: |
            # Some random
            # rego code
`),
			},
		},
		{
			description: "constraint template",
			data: `apiVersion: templates.gatekeeper.sh/v1alpha1
kind: ConstraintTemplate  # Confirm comments WAI
metadata:
  name: really_cool_template_metadata_name
spec:
  crd:
    spec:
      names:
        kind: GCPExternalIpAccessConstraint
  targets:
    - target: validation.gcp.forsetisecurity.org
      rego: |
            # Some random
            # rego code
`,
			expected: &ConstraintTemplate{
				GeneratedKind: "GCPExternalIpAccessConstraint",
				Rego: `# Some random
# rego code
`,
				Confg: UnclassifiedConstraintBuilder(&UnclassifiedConfig{
					Group:        "templates.gatekeeper.sh/v1alpha1",
					MetadataName: "really_cool_template_metadata_name",
					Kind:         "ConstraintTemplate",
					FilePath:     "constraint template", // will be a copy of the description
				}, `apiVersion: templates.gatekeeper.sh/v1alpha1
kind: ConstraintTemplate  # Confirm comments WAI
metadata:
  name: really_cool_template_metadata_name
spec:
  crd:
    spec:
      names:
        kind: GCPExternalIpAccessConstraint
  targets:
    - target: validation.gcp.forsetisecurity.org
      rego: |
            # Some random
            # rego code
`),
			},
		},
		{
			description: "invalid constraint uses template kind",
			data: `apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: ConstraintTemplate # Error Here
metadata:
  name: really_cool_constraint_metadata_name
`,
			wantErr: true,
		},
		{
			description: "invalid constraint uses template api version",
			data: `apiVersion: templates.gatekeeper.sh/v1alpha1 # Error here
kind: KindWillConnectWithTemplate
metadata:
  name: really_cool_constraint_metadata_name
`,
			wantErr: true,
		},
		{
			description: "invalid constraint uses invalid api version",
			data: `apiVersion: INVALID_DATA # Error here
kind: KindWillConnectWithTemplate
metadata:
  name: really_cool_constraint_metadata_name
`,
			wantErr: true,
		},
		{
			description: "invalid constraint no kind",
			data: `apiVersion: constraints.gatekeeper.sh/v1alpha1
metadata:
  name: really_cool_constraint_metadata_name
`,
			wantErr: true,
		},
		{
			description: "invalid constraint no metadata",
			data: `apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: KindWillConnectWithTemplate
`,
			wantErr: true,
		},
		{
			description: "invalid constraint no api version",
			data: `kind: KindWillConnectWithTemplate
metadata:
  name: really_cool_constraint_metadata_name
`,
			wantErr: true,
		},
		{
			description: "parse constraint",
			data: `apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: KindWillConnectWithTemplate
metadata:
  name: really_cool_constraint_metadata_name
`,
			expected: &Constraint{
				Confg: UnclassifiedConstraintBuilder(&UnclassifiedConfig{
					Group:        "constraints.gatekeeper.sh/v1alpha1",
					MetadataName: "really_cool_constraint_metadata_name",
					Kind:         "KindWillConnectWithTemplate",
					FilePath:     "parse constraint", // will be a copy of the description
				}, `apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: KindWillConnectWithTemplate
metadata:
  name: really_cool_constraint_metadata_name
`),
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := CategorizeYAMLFile([]byte(tc.data), tc.description)
			gotErr := (err != nil)
			if tc.wantErr != gotErr {
				t.Errorf("want err %v, got %v", tc.wantErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tc.expected, result, cmpopts.IgnoreUnexported(simpleyaml.Yaml{})); diff != "" {
				t.Errorf("%s (-want, +got) %v", tc.description, diff)
			}
		})
	}
}

func UnclassifiedConstraintBuilder(existingConfig *UnclassifiedConfig, validYaml string) *UnclassifiedConfig {
	yaml, err := simpleyaml.NewYaml([]byte(validYaml))
	if err != nil {
		log.Fatal(err)
	}
	existingConfig.Yaml = yaml
	existingConfig.RawFile = validYaml
	return existingConfig
}
