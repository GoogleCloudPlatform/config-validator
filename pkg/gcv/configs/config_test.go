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

package configs

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/smallfish/simpleyaml"
)

type fileToScan struct {
	path     string
	data     string // optional
	expected bool
}

func TestListYAMLFiles(t *testing.T) {
	testCases := []struct {
		description  string
		listFunction func(string) ([]string, error)
		fileState    []fileToScan
	}{
		{
			description:  "listFiles",
			listFunction: listFiles,
			fileState: []fileToScan{
				{path: "rootFile", expected: true},
				{path: "root.file", expected: true},
				{path: "root.yaml", expected: true},
				{path: "root.rego", expected: true},
				{path: "ROOT.POTATO", expected: true},
				{path: "/dir/nested.file", expected: true},
				{path: "/dir/nested.yaml", expected: true},
				{path: "/dir/nested.rego", expected: true},
				{path: "/dir/nested_test.rego", expected: true},
				{path: "/a/really/multi/nested.file", expected: true},
				{path: "/a/really/multi/nested.yaml", expected: true},
				{path: "/a/really/multi/nested.rego", expected: true},
				{path: "/a/really/multi/nested_test.rego", expected: true},
			},
		},
		{
			description:  "ListYAMLFiles",
			listFunction: ListYAMLFiles,
			fileState: []fileToScan{
				{path: "notYamlfile.lol", expected: false},
				// file contents should be ignored
				{path: "malformed.yaml", data: "impro\"per y'a'm'l format", expected: true},
				{path: "valid.yaml", data: "really_valid_things: yes", expected: true},
				{path: "CAPS.YAML", expected: true},
				{path: "MiXeD.YaMl", expected: true},
				{path: "/nested_directory/with_some.yaml", expected: true},
				{path: "/some/dir/with.yaml", expected: true},
				{path: "/some/dir/multiple.yaml", expected: true},
				{path: "/some/dir/files.yaml", expected: true},
				{path: "/some/dir/andOther.files", expected: false},
				{path: "/a/really/nested_directory/with_some.yaml", expected: true},
			},
		},
		{
			description:  "ListRegoFiles",
			listFunction: ListRegoFiles,
			fileState: []fileToScan{
				{path: "notRegofile.lol", expected: false},
				// file contents should be ignored
				{path: "malformed.rego", data: "what even i\"s r'e'g'u format", expected: true},
				{path: "valid.rego", data: "really_valid_things: yes", expected: true},
				{path: "CAPS.REGO", expected: true},
				{path: "MiXeD.ReGo", expected: true},
				{path: "/nested_directory/with_some.rego", expected: true},
				{path: "/some/dir/with.rego", expected: true},
				{path: "/some/dir/multiple.rego", expected: true},
				{path: "/some/dir/files.rego", expected: true},
				{path: "/some/dir/andOther.files", expected: false},
				{path: "/a/really/nested_directory/with_some.rego", expected: true},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			tmpDir, err := ioutil.TempDir("", "TestListFiles")
			if err != nil {
				t.Fatal("creating temp dir:", err)
			}
			defer cleanupTmpDir(t, tmpDir)
			// create files and expected list
			var expectedFiles []string
			for _, fileData := range tc.fileState {
				filePath := filepath.Join(tmpDir, fileData.path)
				if err := os.MkdirAll(filepath.Dir(filePath), 0777); err != nil {
					t.Fatalf("error creating parent dirs (%s): %v", filePath, err)
				}
				if err := ioutil.WriteFile(filePath, []byte(fileData.data), os.ModeAppend); err != nil {
					t.Fatalf("error creating file (%s): %v", fileData.path, err)
				}
				if fileData.expected {
					expectedFiles = append(expectedFiles, filePath)
				}
			}

			scannedFiles, err := tc.listFunction(tmpDir)

			diff := cmp.Diff(expectedFiles, scannedFiles, cmpopts.SortSlices(func(a, b string) bool { return strings.Compare(a, b) > 0 }))
			if diff != "" {
				t.Errorf("unexpected file scan (-want +got) %v", diff)
			}
		})
	}
}

func TestListFilesEmptyDir(t *testing.T) {
	testCases := []struct {
		description  string
		listFunction func(string) ([]string, error)
	}{
		{description: "listFiles", listFunction: listFiles},
		{description: "ListYAMLFiles", listFunction: ListYAMLFiles},
		{description: "ListRegoFiles", listFunction: ListRegoFiles},
	}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			tmpDir, err := ioutil.TempDir("", "TestListFilesEmptyDir")
			if err != nil {
				t.Fatal("creating temp dir:", err)
			}
			defer cleanupTmpDir(t, tmpDir)
			scannedFiles, err := tc.listFunction(tmpDir)

			diff := cmp.Diff([]string{}, scannedFiles)
			if diff != "" {
				t.Errorf("unexpected file scan (-want +got) %v", diff)
			}
		})
	}
}

func TestListFilesInvalidDirPerms(t *testing.T) {
	testCases := []struct {
		description  string
		listFunction func(string) ([]string, error)
	}{
		{description: "listFiles", listFunction: listFiles},
		{description: "ListYAMLFiles", listFunction: ListYAMLFiles},
		{description: "ListRegoFiles", listFunction: ListRegoFiles},
	}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			tmpDir, err := ioutil.TempDir("", "TestListFilesEmptyDir")
			if err != nil {
				t.Fatal("creating temp dir:", err)
			}
			defer cleanupTmpDir(t, tmpDir)
			// create dir with restrictive permissions
			if err := os.MkdirAll(filepath.Join(tmpDir, "invalidDir"), 0000); err != nil {
				t.Fatal("creating temp dir sub dir:", err)
			}

			_, err = tc.listFunction(tmpDir)

			if err == nil {
				t.Fatal("expected permission error, got none")
			}
		})
	}

}

func TestCategorizeYAMLFile(t *testing.T) {
	testCases := []struct {
		description string
		data        string
		expected    interface{}
		errExpected bool
	}{
		{
			description: "empty file",
			data:        "",
			errExpected: true,
		},
		{
			description: "invalid yaml",
			data:        "dis ain't yaml!",
			errExpected: true,
		},
		{
			description: "invalid template kind",
			data: `apiVersion: gatekeeper.sh/v1
kind: INCORRECT_KIND  # Error here
metadata:
  name: really_cool_template_metadata_name
spec:
  crd:
    spec:
      names:
        kind: GCPExternalIpAccessConstraint
  targets:
   admission.kubernetes.gatekeeper.sh:
      rego: |
            # Some random
            # rego code
`,
			errExpected: true,
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
   admission.kubernetes.gatekeeper.sh:
      rego: |
            # Some random
            # rego code
`,
			errExpected: true,
		},
		{
			description: "invalid template api version (using constraint kind)",
			data: `apiVersion: constraints.gatekeeper.sh/v1  # Error here
kind: ConstraintTemplate
metadata:
  name: really_cool_template_metadata_name
spec:
  crd:
    spec:
      names:
        kind: GCPExternalIpAccessConstraint
  targets:
   admission.kubernetes.gatekeeper.sh:
      rego: |
            # Some random
            # rego code
`,
			errExpected: true,
		},
		{
			description: "invalid template invalid target",
			data: `apiVersion: gatekeeper.sh/v1
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
			errExpected: true,
		},
		{
			description: "invalid template no generated kind",
			data: `apiVersion: gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: really_cool_template_metadata_name
spec:
  crd:
    spec:
      names:
        kind_doesnt_exist': GCPExternalIpAccessConstraint # Error here
  targets:
   admission.kubernetes.gatekeeper.sh:
      rego: |
            # Some random
            # rego code
`,
			errExpected: true,
		},
		{
			description: "parse template",
			data: `apiVersion: gatekeeper.sh/v1
kind: ConstraintTemplate  # Confirm comments WAI
metadata:
  name: really_cool_template_metadata_name
spec:
  crd:
    spec:
      names:
        kind: GCPExternalIpAccessConstraint
  targets:
   admission.kubernetes.gatekeeper.sh:
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
					Group:        "gatekeeper.sh/v1",
					MetadataName: "really_cool_template_metadata_name",
					Kind:         "ConstraintTemplate",
					FilePath:     "parse template", // will be a copy of the description
				}, `apiVersion: gatekeeper.sh/v1
kind: ConstraintTemplate  # Confirm comments WAI
metadata:
  name: really_cool_template_metadata_name
spec:
  crd:
    spec:
      names:
        kind: GCPExternalIpAccessConstraint
  targets:
   admission.kubernetes.gatekeeper.sh:
      rego: |
            # Some random
            # rego code
`),
			},
		},
		{
			description: "invalid constraint uses template kind",
			data: `apiVersion: constraints.gatekeeper.sh/v1
kind: ConstraintTemplate # Error Here
metadata:
  name: really_cool_constraint_metadata_name
`,
			errExpected: true,
		},
		{
			description: "invalid constraint uses template api version",
			data: `apiVersion: gatekeeper.sh/v1 # Error here
kind: KindWillConnectWithTemplate
metadata:
  name: really_cool_constraint_metadata_name
`,
			errExpected: true,
		},
		{
			description: "invalid constraint uses invalid api version",
			data: `apiVersion: INVALID_DATA # Error here
kind: KindWillConnectWithTemplate
metadata:
  name: really_cool_constraint_metadata_name
`,
			errExpected: true,
		},
		{
			description: "invalid constraint no kind",
			data: `apiVersion: constraints.gatekeeper.sh/v1
metadata:
  name: really_cool_constraint_metadata_name
`,
			errExpected: true,
		},
		{
			description: "invalid constraint no metadata",
			data: `apiVersion: constraints.gatekeeper.sh/v1
kind: KindWillConnectWithTemplate
`,
			errExpected: true,
		},
		{
			description: "invalid constraint no api version",
			data: `kind: KindWillConnectWithTemplate
metadata:
  name: really_cool_constraint_metadata_name
`,
			errExpected: true,
		},
		{
			description: "parse constraint",
			data: `apiVersion: constraints.gatekeeper.sh/v1
kind: KindWillConnectWithTemplate
metadata:
  name: really_cool_constraint_metadata_name
`,
			expected: &Constraint{
				Confg: UnclassifiedConstraintBuilder(&UnclassifiedConfig{
					Group:        "constraints.gatekeeper.sh/v1",
					MetadataName: "really_cool_constraint_metadata_name",
					Kind:         "KindWillConnectWithTemplate",
					FilePath:     "parse constraint", // will be a copy of the description
				}, `apiVersion: constraints.gatekeeper.sh/v1
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
			if diff := cmp.Diff(tc.expected, result, cmpopts.IgnoreUnexported(simpleyaml.Yaml{})); diff != "" {
				t.Errorf("%s (-want, +got) %v", tc.description, diff)
			}
			if err == nil && tc.errExpected {
				t.Errorf("want err %v got %v", tc.errExpected, err)
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

func cleanupTmpDir(t *testing.T, dir string) {
	if err := os.RemoveAll(dir); err != nil {
		t.Log(err)
	}
}
