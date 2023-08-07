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

type reviewAssetTestcase struct {
	name           string
	assetJson      string
	asset          *validator.Asset
	wantViolations int
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
		{
			name:           "test iam policy",
			assetJson:      iamPolicyJSON,
			wantViolations: 0,
		},
		{
			name:           "test resource",
			assetJson:      resourceAssetJSON,
			wantViolations: 0,
		},
		{
			name:           "test org_policy",
			assetJson:      orgPolicyJSON,
			wantViolations: 0,
		},
		{
			name:           "test v2_org_policies",
			assetJson:      orgPolicyPolicyJSON,
			wantViolations: 0,
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
func TestCreateNoDir(t *testing.T) {
	emptyFolder, err := os.MkdirTemp("", "emptyPolicyDir")
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
	tmpDir, err := os.MkdirTemp("", "InvalidAccessTest")
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
	policyDir, err := os.MkdirTemp("", "emptyPolicyDir")
	defer cleanup(t, policyDir)
	if err != nil {
		t.Fatal(err)
	}
	policyLibDir, err := os.MkdirTemp("", "emptyPolicyDir")
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

var storageAssetNoLoggingJSON = `{
  "name": "//storage.googleapis.com/my-storage-bucket",
  "ancestors": [
    "projects/3",
    "folders/2",
    "organizations/1"
  ],
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

var iamPolicyJSON = `{
  "name": "//cloudresourcemanager.googleapis.com/456",
  "asset_type": "cloudresourcemanager.googleapis.com/Folder",
  "ancestry_path": "organizations/123/folders/456",
  "iam_policy": {
    "bindings": [
      {
        "role": "roles/editor",
        "members": [
          "user:jane@example.com"
        ]
      }
    ]
  }
}`

func iamPolicy() *validator.Asset {
	return mustMakeAsset(iamPolicyJSON)
}

var resourceAssetJSON = `{
  "name": "//bigquery.googleapis.com/projects/123/datasets/test-dataset",
  "asset_type": "bigquery.googleapis.com/Dataset",
  "ancestry_path": "organizations/12331/folders/2323/project/123",
  "resource": {
    "version": "v2",
    "discovery_document_uri": "https://www.googleapis.com/discovery/v1/apis/bigquery/v2/rest",
    "discovery_name": "Dataset",
    "parent": "//cloudresourcemanager.googleapis.com/projects/123",
    "data": {
      "friendlyName": "",
      "datasetReference": {
        "datasetId": "test-dataset"
      },
      "labels": {
        "env": "dev"
      },
      "location": "EU",
      "defaultTableExpirationMs": 3600000
    }
  }
}`

func resourceAsset() *validator.Asset {
	return mustMakeAsset(resourceAssetJSON)
}

var orgPolicyJSON = `{
  "name": "//cloudresourcemanager.googleapis.com/projects/345",
  "asset_type": "cloudresourcemanager.googleapis.com/Project",
  "org_policy": [
    {
      "constraint": "constraints/compute.disableSerialPortAccess",
      "boolean_policy": {
        "enforced": true
      },
      "update_time": "2021-04-14T15:16:17Z"
    },
    {
      "constraint": "constraints/serviceuser.services",
      "list_policy": {
        "all_values": 1
      },
      "update_time": "2041-04-14T15:17:17Z"
    }
  ],
  "ancestry_path": "organization/1/folder/2/project/345"
}`

func orgPolicy() *validator.Asset {
	return mustMakeAsset(orgPolicyJSON)
}

var orgPolicyPolicyJSON = `
	{
    "name": "//cloudresourcemanager.googleapis.com/projects/123",
    "ancestry_path": "organization/2323/folder/243/project/123",
    "asset_type": "cloudresourcemanager.googleapis.com/Project",
    "v2_org_policies": [
      {
        "name": "projects/123/policies/gcp.resourceLocations",
        "spec": {
          "update_time": "2021-04-14T15:16:17Z",
          "rules": [
            {
              "values": {
                "allowed_values": [
                  "projects/123",
                  "projects/456"
                ],
                "denied_values": [
                  "projects/789"
                ]
              },
              "condition": {
                "expression": "resource.matchLabels('label1', 'label2')",
                "title": "Title of the condition",
                "description": "Description the policy",
                "location": "EU"
              }
            },
            {
              "allow_all": true
            }
          ]
        }
      }
    ]
  }
`

func orgPolicyPolicy() *validator.Asset {
	return mustMakeAsset(orgPolicyPolicyJSON)
}

func mustMakeAsset(assetJSON string) *validator.Asset {
	data := &validator.Asset{}
	if err := jsonpb.UnmarshalString(assetJSON, data); err != nil {
		panic(err)
	}
	return data
}

var defaultReviewTestAssets = []*validator.Asset{
	storageAssetNoLogging(),
	storageAssetWithLogging(),
	storageAssetWithSecureLogging(),
	namespaceAssetWithNoLabel(),
	iamPolicy(),
	resourceAsset(),
	orgPolicy(),
	orgPolicyPolicy(),
}

var defaultReviewTestAssetJSONs = map[string]string{
	"storageAssetNoLoggingJSON":         storageAssetNoLoggingJSON,
	"storageAssetWithLoggingJSON":       storageAssetWithLoggingJSON,
	"storageAssetWithSecureLoggingJSON": storageAssetWithSecureLoggingJSON,
	"namespaceAssetWithNoLabelJSON":     namespaceAssetWithNoLabelJSON,
	"iamPolicyJSON":                     iamPolicyJSON,
	"resourceAssetJSON":                 resourceAssetJSON,
	"orgPolicyJSON":                     orgPolicyJSON,
	"orgPolicyPolicyJSON":               orgPolicyPolicyJSON,
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

type reviewTFResourceChangeBadInputTestcase struct {
	name           string
	resourceChange map[string]interface{}
	wantError      bool
}

func TestReviewTFResourceChangeBadInput(t *testing.T) {
	missingNameResourceChange := computeInstanceResourceChange()
	delete(missingNameResourceChange, "name")

	missingAddressResourceChange := computeInstanceResourceChange()
	delete(missingAddressResourceChange, "address")

	missingTypeResourceChange := computeInstanceResourceChange()
	delete(missingTypeResourceChange, "type")

	missingChangeResourceChange := computeInstanceResourceChange()
	delete(missingChangeResourceChange, "change")
	var testCases = []reviewTFResourceChangeBadInputTestcase{
		{
			name:           "base valid scenario",
			resourceChange: computeInstanceResourceChange(),
			wantError:      false,
		},
		{
			name:           "missing name",
			resourceChange: missingNameResourceChange,
			wantError:      true,
		},
		{
			name:           "missing address",
			resourceChange: missingAddressResourceChange,
			wantError:      true,
		},
		{
			name:           "missing change",
			resourceChange: missingChangeResourceChange,
			wantError:      true,
		},
		{
			name:           "missing type",
			resourceChange: missingTypeResourceChange,
			wantError:      true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewValidator(testOptions())
			if err != nil {
				t.Fatal("unexpected error", err)
			}

			violations, err := v.ReviewTFResourceChange(context.Background(), tc.resourceChange)
			if tc.wantError && err == nil {
				t.Errorf("wanted error but got %d violations", len(violations))
			}
			if !tc.wantError && err != nil {
				t.Errorf("wanted no error but got %s", err)
			}
		})
	}
}

type reviewTFResourceChangeTestcase struct {
	name           string
	resourceChange map[string]interface{}
	wantViolations int
}

func TestReviewTFResourceChange(t *testing.T) {
	var testCases = []reviewTFResourceChangeTestcase{
		{
			name:           "test base valid scenario",
			resourceChange: computeInstanceResourceChange(),
			wantViolations: 0,
		},
		{
			name:           "test base invalid machine_type",
			resourceChange: computeInstanceResourceChangeWithDisallowedMachineType(),
			wantViolations: 1,
		},
		{
			name:           "test with no machine type",
			resourceChange: computeInstanceResourceChangeWithoutMachineType(),
			wantViolations: 1,
		},
		{
			name:           "test unaffected resource_type",
			resourceChange: kmsKeyRingResourceChange(),
			wantViolations: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewValidator(testOptions())
			if err != nil {
				t.Fatal("unexpected error", err)
			}

			violations, err := v.ReviewTFResourceChange(context.Background(), tc.resourceChange)
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

// Artificially removing the after_unknown block to keep this shorter.
var computeInstanceResourceChangeJSON = `{
  "address": "google_compute_instance.foobar",
  "mode": "managed",
  "type": "google_compute_instance",
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
      "machine_type": "e2-medium",
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
    "after_unknown": {}
  }
}`

func computeInstanceResourceChange() map[string]interface{} {
	return mustMakeResourceChange(computeInstanceResourceChangeJSON)
}

// Artificially removing the after_unknown block to keep this shorter.
var computeInstanceResourceChangeWithDisallowedMachineTypeJSON = `{
  "address": "google_compute_instance.foobar",
  "mode": "managed",
  "type": "google_compute_instance",
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
      "machine_type": "e2-high",
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
    "after_unknown": {}
  }
}`

func computeInstanceResourceChangeWithDisallowedMachineType() map[string]interface{} {
	return mustMakeResourceChange(computeInstanceResourceChangeWithDisallowedMachineTypeJSON)
}

// Artificially removing the after_unknown block to keep this shorter.
var computeInstanceResourceChangeWithoutMachineTypeJSON = `{
  "address": "google_compute_instance.foobar",
  "mode": "managed",
  "type": "google_compute_instance",
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
      "machine_type": "",
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
    "after_unknown": {}
  }
}`

func computeInstanceResourceChangeWithoutMachineType() map[string]interface{} {
	return mustMakeResourceChange(computeInstanceResourceChangeWithoutMachineTypeJSON)
}

var kmsKeyRingResourceChangeJSON = `{
  "address": "google_kms_key_ring.test",
  "mode": "managed",
  "type": "google_kms_key_ring",
  "name": "test",
  "provider_name": "google",
  "change": {
    "actions": [
      "create"
    ],
    "before": null,
    "after": {
      "location": "global",
      "name": "keyring-example",
      "timeouts": null
    },
    "after_unknown": {
      "id": true,
      "project": true,
      "self_link": true
    }
  }
}`

func kmsKeyRingResourceChange() map[string]interface{} {
	return mustMakeResourceChange(kmsKeyRingResourceChangeJSON)
}

func mustMakeResourceChange(resourceChangeJSON string) map[string]interface{} {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(resourceChangeJSON), &data); err != nil {
		panic(err)
	}
	return data
}

var defaultReviewTestResourceChanges = []map[string]interface{}{
	computeInstanceResourceChange(),
	computeInstanceResourceChangeWithDisallowedMachineType(),
	computeInstanceResourceChangeWithoutMachineType(),
	kmsKeyRingResourceChange(),
}

func BenchmarkReviewResourceChange(b *testing.B) {
	v, err := NewValidator(testOptions())
	if err != nil {
		b.Fatal("unexpected error", err)
	}

	b.ResetTimer()
	for _, rc := range defaultReviewTestResourceChanges {
		rc := rc
		b.Run(rc["address"].(string), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err = v.ReviewTFResourceChange(context.Background(), rc)
				if err != nil {
					b.Fatalf("unexpected error %s", err)
				}
			}
		})
	}
}
