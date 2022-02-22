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
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

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
				t.Errorf("input %s got %s, want %s", tc.input, got, tc.want)
			}
		})
	}
}

func TestNewConfiguration(t *testing.T) {
	config, err := NewConfiguration([]string{"../../../test/cf"}, "../../../test/cf/library")
	if err != nil {
		t.Fatalf("unexpected error %s", err)
	}

	var got, want int
	got = len(config.GCPTemplates)
	want = 4
	if want != got {
		t.Errorf("len(GCPTemplates) got %d, want %d", got, want)
	}
	got = len(config.GCPConstraints)
	want = 2
	if want != got {
		t.Errorf("len(GCPConstraints) got %d, want %d", got, want)
	}
	got = len(config.K8STemplates)
	want = 1
	if want != got {
		t.Errorf("len(K8STemplates) got %d, want %d", got, want)
	}
	got = len(config.K8SConstraints)
	want = 1
	if want != got {
		t.Errorf("len(K8SConstraints) got %d, want %d", got, want)
	}

	got = len(config.TFTemplates)
	want = 1
	if want != got {
		t.Errorf("len(TFTemplates) got %d, want %d", got, want)
	}
	got = len(config.TFConstraints)
	want = 1
	if want != got {
		t.Errorf("len(TFConstraints) got %d, want %d", got, want)
	}
}

func TestLegacyTemplateConversion(t *testing.T) {
	var testCases = []struct {
		name  string
		input string
	}{
		{
			name:  "legacy template with schema",
			input: "test/cf/templates/gcp_bq_dataset_location_v1.yaml",
		},
		{
			name:  "legacy template no schema",
			input: "test/cf/templates/gcp_storage_logging_template.yaml",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			unst, err := LoadUnstructured(
				[]string{filepath.Join("..", "..", "..", tc.input)})
			if err != nil {
				t.Fatalf("unexpected error %s", err)
			}
			if len(unst) != 1 {
				t.Fatalf("unst must have exactly one item: %v", unst)
			}

			u := unst[0]
			origName := u.GetName()
			err = convertLegacyConstraintTemplate(u, []string{})
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			// Check annotation for new name
			origNameAnnotation, found, err := unstructured.NestedString(u.Object, "metadata", "annotations", OriginalName)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if !found {
				t.Fatal("original name annotation not found")
			}
			if origNameAnnotation != origName {
				t.Errorf("original name annotation has wrong value want %s got %s", origName, origNameAnnotation)
			}
		})
	}
}

func TestLegacyConstraintConversion(t *testing.T) {

}
