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
	"testing"
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
	want = 3
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
}
