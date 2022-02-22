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
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"cloud.google.com/go/storage"
	"github.com/google/go-cmp/cmp"
)

type pathTestcase struct {
	name       string
	path       string
	predicates []readPredicate
	wantError  bool
	wantFiles  []string
}

func (tc *pathTestcase) Run(t *testing.T) {
	p, err := NewPath(tc.path)
	if err != nil {
		t.Fatalf("unexpected error %s", err)
	}

	files, err := p.ReadAll(context.Background(), tc.predicates...)
	if tc.wantError {
		if err == nil {
			t.Fatal("wanted error from p.ReadAll, got none")
		}
	} else {
		if err != nil {
			t.Fatalf("unexpected error %s", err)
		}
	}

	var gotFiles []string
	for _, f := range files {
		gotFiles = append(gotFiles, f.Path)
	}
	sort.Strings(gotFiles)
	sort.Strings(tc.wantFiles)

	if diff := cmp.Diff(tc.wantFiles, gotFiles); diff != "" {
		t.Errorf("Mismatch diff (-want, +got):\n%s\n", diff)
	}
}

var pathTestCases = []pathTestcase{
	{
		name: "no predicates",
		path: "../../../test/cf",
		wantFiles: []string{
			"../../../test/cf/constraints/all_namespace_must_have_cost_center.yaml",
			"../../../test/cf/constraints/cf_gcp_storage_logging_constraint.yaml",
			"../../../test/cf/constraints/gcp_storage_logging_constraint.yaml",
			"../../../test/cf/constraints/tf_compute_instance_mt_constraint.yaml",
			"../../../test/cf/invalid_templates/cf_http_send_v1.yaml",
			"../../../test/cf/library/constraints.rego",
			"../../../test/cf/library/util.rego",
			"../../../test/cf/templates/cf_gcp_storage_logging_template.yaml",
			"../../../test/cf/templates/gcp_bq_dataset_location_v1.yaml",
			"../../../test/cf/templates/gcp_storage_logging_template.yaml",
			"../../../test/cf/templates/k8srequiredlabels_template.yaml",
			"../../../test/cf/templates/tf_compute_instance_machine_type.yaml",
		},
	},
	{
		name:       "yaml only",
		path:       "../../../test/cf",
		predicates: []readPredicate{SuffixPredicate(".yaml")},
		wantFiles: []string{
			"../../../test/cf/constraints/all_namespace_must_have_cost_center.yaml",
			"../../../test/cf/constraints/cf_gcp_storage_logging_constraint.yaml",
			"../../../test/cf/constraints/gcp_storage_logging_constraint.yaml",
			"../../../test/cf/constraints/tf_compute_instance_mt_constraint.yaml",
			"../../../test/cf/invalid_templates/cf_http_send_v1.yaml",
			"../../../test/cf/templates/cf_gcp_storage_logging_template.yaml",
			"../../../test/cf/templates/gcp_bq_dataset_location_v1.yaml",
			"../../../test/cf/templates/gcp_storage_logging_template.yaml",
			"../../../test/cf/templates/k8srequiredlabels_template.yaml",
			"../../../test/cf/templates/tf_compute_instance_machine_type.yaml",
		},
	},
	{
		name:       "rego only",
		path:       "../../../test/cf",
		predicates: []readPredicate{SuffixPredicate(".rego")},
		wantFiles: []string{
			"../../../test/cf/library/constraints.rego",
			"../../../test/cf/library/util.rego",
		},
	},
	{
		name:       "no files",
		path:       "../../../test/cf",
		predicates: []readPredicate{SuffixPredicate(".xyz")},
		wantFiles:  nil,
	},
	{
		name:       "single file",
		path:       "../../../test/cf/templates/k8srequiredlabels_template.yaml",
		predicates: []readPredicate{},
		wantFiles:  []string{"../../../test/cf/templates/k8srequiredlabels_template.yaml"},
	},
	{
		name:      "dir / file does not exist",
		path:      "../../../test/cf/xyz",
		wantError: true,
	},
}

func TestLocalPath(t *testing.T) {
	for _, tc := range pathTestCases {
		t.Run(tc.name, tc.Run)
	}
}

func TestGCSPath(t *testing.T) {
	// Mocking out the GCS client would require wrapping storage.Client, storage.BucketHandle and storage.ObjectIterator
	// and creating proper interfaces for it all.  To simplify, I've decided to trade some amount of stability for
	// making the code way less complicated since people shouldn't be modifying the GCS io code much anyway.
	t.Skipf("GCS unit testing is skipped by default since it requries a functioning client to work.")

	testBucket := "<specify test bucket and copy test dir to bucket>"
	client, err := storage.NewClient(context.Background())
	if err != nil {
		t.Fatalf("unexpected error %s", err)
	}

	var gcsTestCases []pathTestcase
	for _, tc := range pathTestCases {
		// shallow copy testcase then update path
		gcsTC := tc
		gcsTC.path = fmt.Sprintf("gs://%s/%s", testBucket, strings.TrimLeft(gcsTC.path, "/."))
		gcsTC.wantFiles = nil
		for _, want := range tc.wantFiles {
			gcsTC.wantFiles = append(gcsTC.wantFiles, fmt.Sprintf("gs://%s/%s", testBucket, strings.TrimLeft(want, "/.")))
		}
		gcsTestCases = append(gcsTestCases, gcsTC)
	}

	client.Bucket(testBucket)
	for _, tc := range gcsTestCases {
		t.Run(tc.name, tc.Run)
	}
}
