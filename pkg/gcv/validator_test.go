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

package gcv

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/forseti-security/config-validator/pkg/api/validator"
	"github.com/golang/protobuf/jsonpb"
)

const (
	testRoot          = "../../test/cf"
	localPolicyDir    = testRoot
	localPolicyDepDir = testRoot + "/library"
)

func TestCreateValidatorWithNoOptions(t *testing.T) {
	_, err := NewValidator(nil, "/foo")
	if err == nil {
		t.Fatal("expected an error since no policy path is provided")
	}
	_, err = NewValidator([]string{"/foo"}, "")
	if err == nil {
		t.Fatal("expected an error since no policy library path is provided")
	}
}

func TestDefaultTestDataCreatesValidator(t *testing.T) {
	_, err := NewValidator(testOptions())
	if err != nil {
		t.Fatal("unexpected error", err)
	}
}

var defaultReviewTestAssets = []*validator.Asset{
	storageAssetNoLogging(),
	storageAssetWithLogging(),
	storageAssetWithSecureLogging(),
	namespaceAssetWithNoLabel(),
}

type reviewAssetTestcase struct {
	name           string
	asset          *validator.Asset
	wantViolations int
}

func TestReviewAsset(t *testing.T) {
	var testCases = []reviewAssetTestcase{
		{
			name:           "test asset with no logging",
			asset:          storageAssetNoLogging(),
			wantViolations: 2,
		},
		{
			name:           "test asset with logging",
			asset:          storageAssetWithLogging(),
			wantViolations: 0,
		},
		{
			name:           "test asset with secure logging",
			asset:          storageAssetWithSecureLogging(),
			wantViolations: 0,
		},
		{
			name:           "test k8s asset violation",
			asset:          namespaceAssetWithNoLabel(),
			wantViolations: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			v, err := NewValidator(testOptions())
			if err != nil {
				t.Fatal("unexpected error", err)
			}

			violations, err := v.ReviewAsset(context.Background(), tc.asset)
			if err != nil {
				t.Fatal("unexpected error", err)
			}

			got := len(violations)
			if got != tc.wantViolations {
				t.Errorf("wanted %d violations, got %d", tc.wantViolations, got)
			}
		})
	}
}

func TestCreateNoDir(t *testing.T) {
	emptyFolder, err := ioutil.TempDir("", "emptyPolicyDir")
	defer cleanup(t, emptyFolder)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = NewValidator(
		[]string{filepath.Join(emptyFolder, "someDirThatDoesntExist")},
		filepath.Join(emptyFolder, "someDirThatDoesntExist"),
	); err == nil {
		t.Fatal("expected a file system error but got no error")
	}
}

func TestCreateNoReadAccess(t *testing.T) {
	if _, ok := os.LookupEnv("CLOUDBUILD"); ok {
		t.Logf("Skipping %s in Cloud Build environment", t.Name())
		return
	}
	tmpDir, err := ioutil.TempDir("", "InvalidAccessTest")
	if err != nil {
		t.Fatal("creating temp dir:", err)
	}
	defer cleanup(t, tmpDir)
	// create dir with restrictive permissions
	if err := os.MkdirAll(filepath.Join(tmpDir, "invalidDir"), 0000); err != nil {
		t.Fatal("creating temp dir sub dir:", err)
	}

	if _, err = NewValidator([]string{tmpDir}, tmpDir); err == nil {
		t.Fatal("expected a file system error but got no error")
	}
}

func TestCreateEmptyDir(t *testing.T) {
	policyDir, err := ioutil.TempDir("", "emptyPolicyDir")
	defer cleanup(t, policyDir)
	if err != nil {
		t.Fatal(err)
	}
	policyLibDir, err := ioutil.TempDir("", "emptyPolicyDir")
	defer cleanup(t, policyLibDir)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = NewValidator([]string{policyDir}, policyLibDir); err == nil {
		t.Fatal("directory without a configuration should generate error")
	}
}

func cleanup(t *testing.T, dir string) {
	if err := os.RemoveAll(dir); err != nil {
		t.Log(err)
	}
}

// testOptions provides a set of default options that allows the successful creation
// of a validator.
func testOptions() ([]string, string) {
	// Add default options to this list
	return []string{localPolicyDir}, localPolicyDepDir
}

var defaultReviewTestAssetJSONs = map[string]string{
	"storageAssetNoLoggingJSON":         storageAssetNoLoggingJSON,
	"storageAssetWithLoggingJSON":       storageAssetWithLoggingJSON,
	"storageAssetWithSecureLoggingJSON": storageAssetWithSecureLoggingJSON,
	"namespaceAssetWithNoLabelJSON":     namespaceAssetWithNoLabelJSON,
}

var storageAssetNoLoggingJSON = `{
  "name": "//storage.googleapis.com/my-storage-bucket",
  "ancestry_path": "organization/1/folder/2/project/3",
  "asset_type": "storage.googleapis.com/Bucket",
  "resource": {
    "version": "v1",
    "discovery_document_uri": "https://www.googleapis.com/discovery/v1/apis/storage/v1/rest",
    "discovery_name": "Bucket",
    "parent": "//cloudresourcemanager.googleapis.com/projects/68478495408",
    "data": {
      "acl": [],
      "billing": {},
      "cors": [],
      "defaultObjectAcl": [],
      "encryption": {},
      "etag": "CAI=",
      "iamConfiguration": {
        "bucketPolicyOnly": {}
      },
      "id": "my-storage-bucket",
      "kind": "storage#bucket",
      "labels": {},
      "lifecycle": {
        "rule": []
      },
      "location": "US-CENTRAL1",
      "logging": {},
      "metageneration": 2,
      "name": "my-storage-bucket",
      "owner": {},
      "projectNumber": 68478495408,
      "retentionPolicy": {},
      "selfLink": "https://www.googleapis.com/storage/v1/b/my-storage-bucket",
      "storageClass": "STANDARD",
      "timeCreated": "2018-07-23T17:30:22.691Z",
      "updated": "2018-07-23T17:30:23.324Z",
      "versioning": {},
      "website": {}
    }
  }
}`

func storageAssetNoLogging() *validator.Asset {
	return mustMakeAsset(storageAssetNoLoggingJSON)
}

var storageAssetWithLoggingJSON = `{
  "name": "//storage.googleapis.com/my-storage-bucket-with-logging",
  "ancestry_path": "organization/1/folder/2/project/3",
  "asset_type": "storage.googleapis.com/Bucket",
  "resource": {
    "version": "v1",
    "discovery_document_uri": "https://www.googleapis.com/discovery/v1/apis/storage/v1/rest",
    "discovery_name": "Bucket",
    "parent": "//cloudresourcemanager.googleapis.com/projects/68478495408",
    "data": {
      "acl": [],
      "billing": {},
      "cors": [],
      "defaultObjectAcl": [],
      "encryption": {},
      "etag": "CAI=",
      "iamConfiguration": {
        "bucketPolicyOnly": {}
      },
      "id": "my-storage-bucket",
      "kind": "storage#bucket",
      "labels": {},
      "lifecycle": {
        "rule": []
      },
      "location": "US-CENTRAL1",
      "logging": {
        "logBucket": "example-logs-bucket",
        "logObjectPrefix": "log_object_prefix"
      },
      "metageneration": 2,
      "name": "my-storage-bucket-with-logging",
      "owner": {},
      "projectNumber": 68478495408,
      "retentionPolicy": {},
      "selfLink": "https://www.googleapis.com/storage/v1/b/my-storage-bucket",
      "storageClass": "STANDARD",
      "timeCreated": "2018-07-23T17:30:22.691Z",
      "updated": "2018-07-23T17:30:23.324Z",
      "versioning": {},
      "website": {}
    }
  }
}`

func storageAssetWithLogging() *validator.Asset {
	return mustMakeAsset(storageAssetWithLoggingJSON)
}

var storageAssetWithSecureLoggingJSON = `{
  "name": "//storage.googleapis.com/my-storage-bucket-with-secure-logging",
  "asset_type": "storage.googleapis.com/Bucket",
  "ancestry_path": "organization/1/folder/2/project/3",
  "resource": {
    "version": "v1",
    "discovery_document_uri": "https://www.googleapis.com/discovery/v1/apis/storage/v1/rest",
    "discovery_name": "Bucket",
    "parent": "//cloudresourcemanager.googleapis.com/projects/68478495408",
    "data": {
      "acl": [],
      "billing": {},
      "cors": [],
      "defaultObjectAcl": [],
      "encryption": {},
      "etag": "CAI=",
      "iamConfiguration": {
        "bucketPolicyOnly": {}
      },
      "id": "my-storage-bucket",
      "kind": "storage#bucket",
      "labels": {},
      "lifecycle": {
        "rule": []
      },
      "location": "US-CENTRAL1",
      "logging": {
        "logBucket": "secure-logs-bucket",
        "logObjectPrefix": "log_object_prefix"
      },
      "metageneration": 2,
      "name": "my-storage-bucket-with-secure-logging",
      "owner": {},
      "projectNumber": 68478495408,
      "retentionPolicy": {},
      "selfLink": "https://www.googleapis.com/storage/v1/b/my-storage-bucket",
      "storageClass": "STANDARD",
      "timeCreated": "2018-07-23T17:30:22.691Z",
      "updated": "2018-07-23T17:30:23.324Z",
      "versioning": {},
      "website": {}
    }
  }
}`

func storageAssetWithSecureLogging() *validator.Asset {
	return mustMakeAsset(storageAssetWithSecureLoggingJSON)
}

var namespaceAssetWithNoLabelJSON = `
{
  "name": "//container.googleapis.com/projects/malaise-forever/zones/us-central1-a/clusters/test-1/k8s/namespaces/whatever",
  "asset_type": "k8s.io/Namespace",
  "ancestry_path": "organization/1234567899/project/1234567890",
  "resource": {
    "version": "v1",
    "discovery_document_uri": "https://raw.githubusercontent.com/kubernetes/kubernetes/master/api/openapi-spec/swagger.json",
    "discovery_name": "io.k8s.api.core.v1.Namespace",
    "parent": "//container.googleapis.com/projects/malaise-forever/zones/us-central1-a/clusters/test-1",
    "data": {
      "metadata": {
        "creationTimestamp": "2019-07-03T21:59:39Z",
        "name": "whatever",
        "resourceVersion": "33",
        "selfLink": "/api/v1/namespaces/whatever",
        "uid": "dac58e10-9ddd-11e9-bd7a-42010a800008"
      },
      "spec": {
        "finalizers": [
          "kubernetes"
        ]
      },
      "status": {
        "phase": "Active"
      }
    }
  },
  "ancestors": [
    "projects/1234567890",
    "organizations/1234567899"
  ]
}
`

func namespaceAssetWithNoLabel() *validator.Asset {
	return mustMakeAsset(namespaceAssetWithNoLabelJSON)
}

func mustMakeAsset(assetJSON string) *validator.Asset {
	data := &validator.Asset{}
	if err := jsonpb.UnmarshalString(assetJSON, data); err != nil {
		panic(err)
	}
	return data
}

func BenchmarkReviewJSON(b *testing.B) {
	v, err := NewValidator(testOptions())
	if err != nil {
		b.Fatal("unexpected error", err)
	}

	b.ResetTimer()
	for name, asset := range defaultReviewTestAssetJSONs {
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err = v.ReviewJSON(context.Background(), asset)
				if err != nil {
					b.Fatalf("unexpected error %s", err)
				}
			}
		})
	}
}

func BenchmarkReviewAsset(b *testing.B) {
	v, err := NewValidator(testOptions())
	if err != nil {
		b.Fatal("unexpected error", err)
	}

	b.ResetTimer()
	for idx, a := range defaultReviewTestAssets {
		b.Run(a.Name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err = v.ReviewAsset(context.Background(), defaultReviewTestAssets[idx])
				if err != nil {
					b.Fatalf("unexpected error %s", err)
				}
			}
		})
	}
}
