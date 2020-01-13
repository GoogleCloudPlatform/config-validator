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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
			description:  "ListYAMLFiles",
			listFunction: ListYAMLFiles,
			fileState: []fileToScan{
				{path: "notYamlFile.lol", expected: false},
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
				{path: "notRegoFile.lol", expected: false},
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
			defer cleanup(t, tmpDir)
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

			if diff := cmp.Diff(
				expectedFiles,
				scannedFiles,
				cmpopts.SortSlices(func(a, b string) bool { return strings.Compare(a, b) > 0 }),
			); diff != "" {
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
		{description: "ListYAMLFiles", listFunction: ListYAMLFiles},
		{description: "ListRegoFiles", listFunction: ListRegoFiles},
	}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			tmpDir, err := ioutil.TempDir("", "TestListFilesEmptyDir")
			if err != nil {
				t.Fatal("creating temp dir:", err)
			}
			defer cleanup(t, tmpDir)
			scannedFiles, err := tc.listFunction(tmpDir)

			var want []string
			if diff := cmp.Diff(want, scannedFiles); diff != "" {
				t.Errorf("unexpected file scan (-want +got) %v", diff)
			}
		})
	}
}

func TestListFilesInvalidDirPerms(t *testing.T) {
	if _, ok := os.LookupEnv("CLOUDBUILD"); ok {
		t.Logf("Skipping %s in Cloud Build environment", t.Name())
		return
	}
	testCases := []struct {
		description  string
		listFunction func(string) ([]string, error)
	}{
		{description: "ListYAMLFiles", listFunction: ListYAMLFiles},
		{description: "ListRegoFiles", listFunction: ListRegoFiles},
	}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			tmpDir, err := ioutil.TempDir("", "TestListFilesEmptyDir")
			if err != nil {
				t.Fatal("creating temp dir:", err)
			}
			defer cleanup(t, tmpDir)
			// create dir with restrictive permissions
			if err := os.MkdirAll(filepath.Join(tmpDir, "invalidDir"), 0000); err != nil {
				t.Fatal("creating temp dir sub dir:", err)
			}

			if _, err := tc.listFunction(tmpDir); err == nil {
				t.Fatal("expected permission error, got none")
			}
		})
	}

}

func cleanup(t *testing.T, dir string) {
	if err := os.RemoveAll(dir); err != nil {
		t.Log(err)
	}
}

func TestFixLegacyMatcher(t *testing.T) {
	var testCases = []struct {
		input string
		want  string
	}{
		{
			"organization/*",
			"organizations/**",
		},
		{
			"folder/*",
			"folders/**",
		},
		{
			"project/*",
			"projects/**",
		},
		{
			"organization/*/folder/*",
			"organizations/**/folders/**",
		},
		{
			"organization/*/project/*",
			"organizations/**/projects/**",
		},
		{
			"organization/*/folder/*/project/*",
			"organizations/**/folders/**/projects/**",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			got := fixLegacyMatcher(tc.input)
			if got != tc.want {
				t.Errorf("input %s wanted %s, got %s", tc.input, tc.want, got)
			}
		})
	}
}
