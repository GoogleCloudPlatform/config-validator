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
	"sync"
	"testing"

	"github.com/forseti-security/config-validator/pkg/api/validator"
	"github.com/golang/protobuf/jsonpb"
	"google.golang.org/genproto/googleapis/cloud/asset/v1"
	"google.golang.org/genproto/googleapis/iam/v1"
)

const (
	testRoot          = "../../test/cf"
	localPolicyDir    = testRoot
	localPolicyDepDir = testRoot + "/library"
)

func TestCreateValidatorWithNoOptions(t *testing.T) {
	stopChannel := make(chan struct{})
	defer close(stopChannel)
	_, err := NewValidator(stopChannel, "", "/foo")
	if err == nil {
		t.Fatal("expected an error since no policy path is provided")
	}
	_, err = NewValidator(stopChannel, "/foo", "")
	if err == nil {
		t.Fatal("expected an error since no policy library path is provided")
	}
}

func TestDefaultTestDataCreatesValidator(t *testing.T) {
	stopChannel := make(chan struct{})
	defer close(stopChannel)
	_, err := NewValidator(testOptions(stopChannel))
	if err != nil {
		t.Fatal("unexpected error", err)
	}
}

func TestAddData(t *testing.T) {
	testCases := []struct {
		description string
		request     *validator.AddDataRequest
		wantErr     bool
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
			wantErr: true,
		},
		{
			description: "nil entry in array",
			request: &validator.AddDataRequest{
				Assets: []*validator.Asset{
					nil,
				},
			},
			wantErr: true,
		},
		{
			description: "non-nil resource",
			request: &validator.AddDataRequest{
				Assets: []*validator.Asset{
					{
						Name:         "Some Name",
						AssetType:    "some type",
						AncestryPath: "some path",
						Resource:     &asset.Resource{},
					},
				},
			},
		},
		{
			description: "non-nil IAM policy",
			request: &validator.AddDataRequest{
				Assets: []*validator.Asset{
					{
						Name:         "Some Name",
						AssetType:    "some type",
						AncestryPath: "some path",
						IamPolicy:    &iam.Policy{},
					},
				},
			},
		},
		{
			description: "nil resource & IAM policy",
			request: &validator.AddDataRequest{
				Assets: []*validator.Asset{
					{
						Name:         "Some Name",
						AssetType:    "some type",
						AncestryPath: "some path",
					},
				},
			},
			wantErr: true,
		},
		{
			description: "missing name",
			request: &validator.AddDataRequest{
				Assets: []*validator.Asset{
					{
						AssetType:    "some type",
						AncestryPath: "some path",
						IamPolicy:    &iam.Policy{},
					},
				},
			},
			wantErr: true,
		},
		{
			description: "missing type",
			request: &validator.AddDataRequest{
				Assets: []*validator.Asset{
					{
						Name:         "Some Name",
						AncestryPath: "some path",
						IamPolicy:    &iam.Policy{},
					},
				},
			},
			wantErr: true,
		},
		{
			description: "missing ancestry path",
			request: &validator.AddDataRequest{
				Assets: []*validator.Asset{
					{
						Name:      "Some Name",
						AssetType: "some type",
						IamPolicy: &iam.Policy{},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			stopChannel := make(chan struct{})
			defer close(stopChannel)
			v, err := NewValidator(testOptions(stopChannel))
			if err != nil {
				t.Fatal("unexpected error", err)
			}
			err = v.AddData(tc.request)
			if (err == nil) == tc.wantErr {
				t.Fatalf("got %v, want err: %t", err, tc.wantErr)
			}
		})
	}

}

func TestAudit(t *testing.T) {
	stopChannel := make(chan struct{})
	defer close(stopChannel)
	v, err := NewValidator(testOptions(stopChannel))
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

	if len(result.Violations) != 1 {
		t.Fatalf("unexpected violation count, wanted 1, got %d", len(result.Violations))
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

type reviewTestcase struct {
	name        string
	workerCount int
	calls       []reviewCall
}

type reviewCall struct {
	assets             []*validator.Asset // assets to use if not using the default asset set
	scaleFactor        int                // number of copies of asset list to put in one call to Review.
	wantViolationCount int                // the total violation count
}

var defaultReviewTestAssets = []*validator.Asset{
	storageAssetNoLogging(),
	storageAssetWithLogging(),
	storageAssetWithSecureLogging(),
}

func TestReview(t *testing.T) {
	// we will run 3x this amount of assets through audit, then reset at end
	// of test.
	var testCases = []reviewTestcase{
		{
			name:        "no assets",
			workerCount: 1,
			calls: []reviewCall{
				{
					assets: []*validator.Asset{},
				},
			},
		},
		{
			name:        "single call",
			workerCount: 1,
			calls: []reviewCall{
				{
					assets:             []*validator.Asset{storageAssetNoLogging()},
					wantViolationCount: 1,
				},
			},
		},
		{
			name:        "single call three assets",
			workerCount: 1,
			calls: []reviewCall{
				{
					assets:             defaultReviewTestAssets,
					wantViolationCount: 1,
				},
			},
		},
	}

	var testCase *reviewTestcase
	testCase = &reviewTestcase{
		name:        "128 goroutines x32 calls x16 scale",
		workerCount: 128,
	}
	for i := 0; i < 32; i++ {
		testCase.calls = append(
			testCase.calls,
			reviewCall{
				assets:             defaultReviewTestAssets,
				scaleFactor:        16,
				wantViolationCount: 1,
			},
		)
	}
	testCases = append(testCases, *testCase)
	testCase = &reviewTestcase{
		name:        "single call large scale deadlock test",
		workerCount: 4,
		calls: []reviewCall{
			{
				assets:             defaultReviewTestAssets,
				scaleFactor:        4 * 16,
				wantViolationCount: 1,
			},
		},
	}
	testCases = append(testCases, *testCase)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oldWorkerCount := flags.workerCount
			defer func() {
				flags.workerCount = oldWorkerCount
			}()
			flags.workerCount = tc.workerCount

			stopChannel := make(chan struct{})
			defer close(stopChannel)

			v, err := NewValidator(testOptions(stopChannel))
			if err != nil {
				t.Fatal("unexpected error", err)
			}

			var groupDone sync.WaitGroup
			for callIdx, call := range tc.calls {
				groupDone.Add(1)
				go func(cIdx int, call reviewCall) {
					defer groupDone.Done()
					if call.scaleFactor == 0 {
						call.scaleFactor = 1
					}

					var assets []*validator.Asset
					for i := 0; i < call.scaleFactor; i++ {
						assets = append(assets, call.assets...)
					}

					result, err := v.Review(context.Background(), &validator.ReviewRequest{
						Assets: assets,
					})
					if err != nil {
						t.Fatalf("review error in call %d: %s", cIdx, err)
					}

					wantViolationCount := call.wantViolationCount * call.scaleFactor
					if len(result.Violations) != wantViolationCount {
						t.Fatalf("wanted %d violations, got %d", wantViolationCount, len(result.Violations))
					}
				}(callIdx, call)
			}
			groupDone.Wait()
		})
	}
}

func TestCreateNoDir(t *testing.T) {
	emptyFolder, err := ioutil.TempDir("", "emptyPolicyDir")
	defer cleanup(t, emptyFolder)
	if err != nil {
		t.Fatal(err)
	}

	stopChannel := make(chan struct{})
	defer close(stopChannel)
	if _, err = NewValidator(
		stopChannel,
		filepath.Join(emptyFolder, "someDirThatDoesntExist"),
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

	stopChannel := make(chan struct{})
	defer close(stopChannel)
	if _, err = NewValidator(stopChannel, tmpDir, tmpDir); err == nil {
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

	stopChannel := make(chan struct{})
	defer close(stopChannel)
	if _, err = NewValidator(stopChannel, policyDir, policyLibDir); err != nil {
		t.Fatal("empty dir not expected to provide error: ", err)
	}
}

func cleanup(t *testing.T, dir string) {
	if err := os.RemoveAll(dir); err != nil {
		t.Log(err)
	}
}

// testOptions provides a set of default options that allows the successful creation
// of a validator.
func testOptions(stopChannel <-chan struct{}) (<-chan struct{}, string, string) {
	// Add default options to this list
	return stopChannel, localPolicyDir, localPolicyDepDir
}

func storageAssetNoLogging() *validator.Asset {
	return mustMakeAsset(`{
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
}`)
}
func storageAssetWithLogging() *validator.Asset {
	return mustMakeAsset(`{
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
}`)
}
func storageAssetWithSecureLogging() *validator.Asset {
	return mustMakeAsset(`{
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
}`)
}

func mustMakeAsset(assetJSON string) *validator.Asset {
	data := &validator.Asset{}
	if err := jsonpb.UnmarshalString(assetJSON, data); err != nil {
		panic(err)
	}
	return data
}
