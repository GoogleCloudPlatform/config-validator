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

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/ptypes/struct"
	"partner-code.googlesource.com/gcv/gcv/pkg/api/validator"
)

const (
	repoRoot          = "../../../"
	localPolicyDir    = repoRoot + "policies/"
	localPolicyDepDir = repoRoot + "policies/validator/lib"
)

func TestCreateValidatorWithNoOptions(t *testing.T) {
	_, err := NewValidator()
	if err == nil {
		t.Fatal("expected an error since no policy path is provided")
	}
}

func TestDefaultTestDataCreatesValidator(t *testing.T) {
	_, err := NewValidator(testOptions())
	if err != nil {
		t.Fatal("unexpected error", err)
	}
}

func TestAddData(t *testing.T) {
	testCases := []struct {
		description string
		request     *validator.AddDataRequest
	}{
		{
			description: "empty request",
			request:     &validator.AddDataRequest{},
		},
		{
			description: "empty array",
			request: &validator.AddDataRequest{
				Assets: []*validator.Asset{},
			},
		},
		{
			description: "empty entry in array",
			request: &validator.AddDataRequest{
				Assets: []*validator.Asset{
					{},
				},
			},
		},
		{
			description: "just string fields",
			request: &validator.AddDataRequest{
				Assets: []*validator.Asset{
					{
						Name:         "Some Name",
						AssetType:    "some type",
						AncestryPath: "some path",
					},
				},
			},
		},
		{
			description: "nil resource",
			request: &validator.AddDataRequest{
				Assets: []*validator.Asset{
					{
						Name:         "Some Name",
						AssetType:    "some type",
						AncestryPath: "some path",
						Resource:     nil,
					},
				},
			},
		},
		{
			description: "empty resource struct",
			request: &validator.AddDataRequest{
				Assets: []*validator.Asset{
					{
						Name:         "Some Name",
						AssetType:    "some type",
						AncestryPath: "some path",
						Resource:     &structpb.Value{},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			v, err := NewValidator(testOptions())
			if err != nil {
				t.Fatal("unexpected error", err)
			}
			err = v.AddData(tc.request)
			if err != nil {
				t.Fatalf("got %v, want nil", err)
			}
		})
	}

}

func TestAudit(t *testing.T) {
	v, err := NewValidator(testOptions())
	if err != nil {
		t.Fatal("unexpected error", err)
	}
	err = v.AddData(&validator.AddDataRequest{
		Assets: []*validator.Asset{
			storageAssetNoLogging(),
			storageAssetWithLogging(),
			storageAssetWithSecureLogging(),
		},
	})
	if err != nil {
		t.Fatal("unexpected error", err)
	}

	result, err := v.Audit(context.Background())
	if err != nil {
		t.Fatal("unexpected error", err)
	}

	if len(result.Violations) == 0 {
		t.Fatal("unexpected violations received none")
	}
	expectedResourceName := storageAssetNoLogging().Name
	foundExpectedViolation := false
	for _, violation := range result.Violations {
		if violation.Resource == expectedResourceName {
			foundExpectedViolation = true
			break
		}
	}
	if !foundExpectedViolation {
		t.Fatalf("unexpected result resource %s not found", expectedResourceName)
	}
}

func TestCreateNoDir(t *testing.T) {
	emptyFolder, err := ioutil.TempDir("", "emptyPolicyDir")
	defer cleanup(t, emptyFolder)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = NewValidator(
		PolicyPath(filepath.Join(emptyFolder, "someDirThatDoesntExist")),
		PolicyLibraryDir(filepath.Join(emptyFolder, "someDirThatDoesntExist")),
	); err == nil {
		t.Fatal("expected a file system error but got no error")
	}
}

func TestCreateNoReadAccess(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "InvalidAccessTest")
	if err != nil {
		t.Fatal("creating temp dir:", err)
	}
	defer cleanup(t, tmpDir)
	// create dir with restrictive permissions
	if err := os.MkdirAll(filepath.Join(tmpDir, "invalidDir"), 0000); err != nil {
		t.Fatal("creating temp dir sub dir:", err)
	}

	if _, err = NewValidator(
		PolicyPath(tmpDir),
		PolicyLibraryDir(tmpDir),
	); err == nil {
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

	if _, err = NewValidator(
		PolicyPath(policyDir),
		PolicyLibraryDir(policyLibDir),
	); err != nil {
		t.Fatal("empty dir not expected to provide error: ", err)
	}
}

func cleanup(t *testing.T, dir string) {
	if err := os.RemoveAll(dir); err != nil {
		t.Log(err)
	}
}

// groupOptions will Groups options in order into a single option.
func groupOptions(options ...Option) Option {
	return func(v *Validator) error {
		for _, option := range options {
			if err := option(v); err != nil {
				return err
			}
		}
		return nil
	}
}

// testOptions provides a set of default options that allows the successful creation
// of a validator.
func testOptions() Option {
	// Add default options to this list
	return groupOptions(
		PolicyPath(localPolicyDir),
		PolicyLibraryDir(localPolicyDepDir),
	)
}

func storageAssetNoLogging() *validator.Asset {
	return mustMakeAsset(`{
  "name": "//storage.googleapis.com/my-storage-bucket",
  "asset_type": "google.cloud.storage.Bucket",
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
}`)
}
func storageAssetWithLogging() *validator.Asset {
	return mustMakeAsset(`{
  "name": "//storage.googleapis.com/my-storage-bucket-with-logging",
  "asset_type": "google.cloud.storage.Bucket",
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
}`)
}
func storageAssetWithSecureLogging() *validator.Asset {
	return mustMakeAsset(`{
  "name": "//storage.googleapis.com/my-storage-bucket-with-secure-logging",
  "asset_type": "google.cloud.storage.Bucket",
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
}`)
}

func mustMakeAsset(assetJson string) *validator.Asset {
	asset := &validator.Asset{}
	if err := jsonpb.UnmarshalString(assetJson, asset); err != nil {
		panic(err)
	}
	return asset
}
