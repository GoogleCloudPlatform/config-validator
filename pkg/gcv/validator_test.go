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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/GoogleCloudPlatform/config-validator/pkg/api/validator"
	"github.com/GoogleCloudPlatform/config-validator/pkg/gcv/configs"
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

func TestDefaultTestDataWithDisabledBuiltins(t *testing.T) {
	policyFilePaths, policyLibPath := testOptions()
	// options.DisabledBuiltins = append(options.DisabledBuiltins, "http.send")
	_, err := NewValidator(policyFilePaths, policyLibPath, DisableBuiltins("http.send"))
	if err == nil {
		t.Fatal("expected an error since http.send was disabled")
	}
}

func TestDefaultTestDataCreatesValidatorFromContents(t *testing.T) {
	policyFilePaths, policyLibPath := testOptions()

	// Load contents of policy files.
	var policyFiles []*configs.PolicyFile
	for _, dir := range policyFilePaths {
		dirPath, err := configs.NewPath(dir)
		if err != nil {
			t.Fatal("unexpected error loading policy constraints", err)
		}
		dirFiles, err := dirPath.ReadAll(context.Background(), configs.SuffixPredicate(".yaml"))
		if err != nil {
			t.Fatal("unexpected error reading .yaml files", err)
		}
		for _, dirFile := range dirFiles {
			policyFiles = append(policyFiles, &configs.PolicyFile{
				Path:    dirFile.Path,
				Content: dirFile.Content,
			})
		}
	}

	// Load contents of policy library.
	policyLibrary, err := configs.LoadRegoFiles(policyLibPath)
	if err != nil {
		t.Fatal("unexpected error loading policy library", err)
	}

	if _, err := NewValidatorFromContents(policyFiles, policyLibrary); err != nil {
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
	assetJson      string
	asset          *validator.Asset
	wantViolations int
}

type reviewTFResourceTestcase struct {
	name          string
	resource      map[string]interface{}
	wantViolation bool
}

func TestReviewAsset(t *testing.T) {
	var testCases = []reviewAssetTestcase{
		{
			name:           "test asset with no logging",
			assetJson:      storageAssetNoLoggingJSON,
			wantViolations: 2,
		},
		{
			name:           "test asset with logging",
			assetJson:      storageAssetWithLoggingJSON,
			wantViolations: 0,
		},
		{
			name:           "test asset with secure logging",
			assetJson:      storageAssetWithSecureLoggingJSON,
			wantViolations: 0,
		},
		{
			name:           "test k8s asset violation",
			assetJson:      namespaceAssetWithNoLabelJSON,
			wantViolations: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewValidator(testOptions())
			if err != nil {
				t.Fatal("unexpected error", err)
			}

			var assetObj map[string]interface{}
			err = json.Unmarshal([]byte(tc.assetJson), &assetObj)
			if err != nil {
				t.Fatal("unexpected error", err)
			}

			result, err := v.ReviewJSON(context.Background(), tc.assetJson)
			if err != nil {
				t.Fatal("unexpected error", err)
			}
			got := len(result.ConstraintViolations)
			if got != tc.wantViolations {
				t.Errorf("wanted %d violations, got %d", tc.wantViolations, got)
			}

			result, err = v.ReviewUnmarshalledJSON(context.Background(), assetObj)
			if err != nil {
				t.Fatal("unexpected error", err)
			}
			got = len(result.ConstraintViolations)
			if got != tc.wantViolations {
				t.Errorf("wanted %d violations, got %d", tc.wantViolations, got)
			}

			violations, err := v.ReviewAsset(context.Background(), mustMakeAsset(tc.assetJson))
			if err != nil {
				t.Fatal("unexpected error", err)
			}
			got = len(violations)
			if got != tc.wantViolations {
				t.Errorf("wanted %d violations, got %d", tc.wantViolations, got)
			}
		})
	}
}

func TestReviewTFResource(t *testing.T) {
	var testCases = []reviewTFResourceTestcase{
		{
			name:          "test base valid scenario",
			resource:      getFirstResourceChange(retrieveTFPlanResourceChangesWith("e2-medium", true), t),
			wantViolation: false,
		},
		{
			name:          "test base invalid machine_type",
			resource:      getFirstResourceChange(retrieveTFPlanResourceChangesWith("e2-high", true), t),
			wantViolation: true,
		},
		{
			name:          "test base invalid resource_type",
			resource:      getFirstResourceChange(retrieveTFPlanResourceChangesWith("e2-medium", false), t),
			wantViolation: true,
		},
		{
			name:          "test with no machine type",
			resource:      getFirstResourceChange(retrieveTFPlanResourceChangesWith("", true), t),
			wantViolation: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewValidator(testOptions())
			if err != nil {
				t.Fatal("unexpected error", err)
			}

			result, err := v.ReviewTFResource(context.Background(), tc.resource)
			if err != nil {
				t.Fatal("unexpected error", err)
			}
			got := len(result.ConstraintViolations) > 0
			if got != tc.wantViolation {
				t.Errorf("wanted violation to be %v, got %v", tc.wantViolation, got)
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

func getFirstResourceChange(tfplan string, t *testing.T) map[string]interface{} {
	var tfplanParsed = map[string]interface{}{}
	var resourceChanges []interface{}
	json.Unmarshal([]byte(tfplan), &tfplanParsed)
	resourceChangesRaw, ok := tfplanParsed["resource_changes"]
	if !ok {
		t.Logf(tfplan)
		t.Fatal("unable to parse tf plan given")
	}

	resourceChanges = resourceChangesRaw.([]interface{})
	resource, ok := resourceChanges[0].(map[string]interface{})
	if !ok {
		t.Logf(tfplan)
		t.Fatal("unable to get resource from array")
	}

	return resource
}

func retrieveTFPlanResourceChangesWith(machineType string, isComputeInstance bool) string {
	var resourceType = "google_compute_instance"
	if !isComputeInstance {
		resourceType = "google_banana_instance"
	}

	machineTypeBlock := ""
	if machineType != "" {
		machineTypeBlock = fmt.Sprintf(`"machine_type": "%s",`, machineType)

	}

	return fmt.Sprintf(`{
  "format_version": "0.1",
  "terraform_version": "0.13.7",
  "planned_values": {},
  "resource_changes": [
    {
      "address": "%s.foobar",
      "mode": "managed",
      "type": "%s",
      "name": "foobar",
      "provider_name": "registry.terraform.io/hashicorp/google",
      "change": {
        "actions": [
          "create"
        ],
        "before": null,
        "after": {
          "advanced_machine_features": [],
          "allow_stopping_for_update": null,
          "attached_disk": [],
          "boot_disk": [
            {
              "auto_delete": true,
              "disk_encryption_key_raw": null,
              "initialize_params": [
                {
                  "image": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-9-stretch-v20220118"
                }
              ],
              "mode": "READ_WRITE"
            }
          ],
          "can_ip_forward": false,
          "deletion_protection": false,
          "description": null,
          "desired_status": null,
          "enable_display": null,
          "hostname": null,
          "labels": {
            "my_key": "my_value",
            "my_other_key": "my_other_value"
          },
          %s
          "metadata": {
            "baz": "qux",
            "foo": "bar",
            "startup-script": "echo Hello"
          },
          "metadata_startup_script": null,
          "name": "meep-merp",
          "network_interface": [
            {
              "access_config": [],
              "alias_ip_range": [],
              "ipv6_access_config": [],
              "network": "default",
              "nic_type": null,
              "queue_count": null
            }
          ],
          "resource_policies": null,
          "scratch_disk": [],
          "service_account": [],
          "shielded_instance_config": [],
          "tags": [
            "bar",
            "foo"
          ],
          "timeouts": null,
          "zone": "us-central1-a"
        },
        "after_unknown": {
          "advanced_machine_features": [],
          "attached_disk": [],
          "boot_disk": [
            {
              "device_name": true,
              "disk_encryption_key_sha256": true,
              "initialize_params": [
                {
                  "labels": true,
                  "size": true,
                  "type": true
                }
              ],
              "kms_key_self_link": true,
              "source": true
            }
          ],
          "confidential_instance_config": true,
          "cpu_platform": true,
          "current_status": true,
          "guest_accelerator": true,
          "id": true,
          "instance_id": true,
          "label_fingerprint": true,
          "labels": {},
          "metadata": {},
          "metadata_fingerprint": true,
          "min_cpu_platform": true,
          "network_interface": [
            {
              "access_config": [],
              "alias_ip_range": [],
              "ipv6_access_config": [],
              "ipv6_access_type": true,
              "name": true,
              "network_ip": true,
              "stack_type": true,
              "subnetwork": true,
              "subnetwork_project": true
            }
          ],
          "project": true,
          "reservation_affinity": true,
          "scheduling": true,
          "scratch_disk": [],
          "self_link": true,
          "service_account": [],
          "shielded_instance_config": [],
          "tags": [
            false,
            false
          ],
          "tags_fingerprint": true
        }
      }
    }
  ],
  "prior_state": {},
  "configuration": {}
}`, resourceType, resourceType, machineTypeBlock)
}
