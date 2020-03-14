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
	"testing"

	"github.com/forseti-security/config-validator/pkg/api/validator"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/google/go-cmp/cmp"
)

type ConversionTestCase struct {
	name           string
	input          string
	wantInsights   []*Insight
	wantViolations []*validator.Violation
}

var conversionTestCases = []ConversionTestCase{
	{
		name:  "storageAssetNoLoggingJSON",
		input: storageAssetNoLoggingJSON,
		wantInsights: []*Insight{
			{
				Description:     "//storage.googleapis.com/my-storage-bucket does not have the required logging destination.",
				TargetResources: []string{"//storage.googleapis.com/my-storage-bucket"},
				InsightSubtype:  "CFGCPStorageLoggingConstraint.require-storage-logging",
				Content: map[string]interface{}{
					"metadata": map[string]interface{}{
						"details": map[string]interface{}{
							"destination_bucket": string(""),
							"resource":           string("//storage.googleapis.com/my-storage-bucket"),
						},
					},
					"resource": map[string]interface{}{
						"ancestry_path": string("organizations/1/folders/2/projects/3"),
						"asset_type":    string("storage.googleapis.com/Bucket"),
						"name":          string("//storage.googleapis.com/my-storage-bucket"),
						"resource": map[string]interface{}{
							"data": map[string]interface{}{
								"acl":              []interface{}{},
								"billing":          map[string]interface{}{},
								"cors":             []interface{}{},
								"defaultObjectAcl": []interface{}{},
								"encryption":       map[string]interface{}{},
								"etag":             string("CAI="),
								"iamConfiguration": map[string]interface{}{"bucketPolicyOnly": map[string]interface{}{}},
								"id":               string("my-storage-bucket"),
								"kind":             string("storage#bucket"),
								"labels":           map[string]interface{}{},
								"lifecycle":        map[string]interface{}{"rule": []interface{}{}},
								"location":         string("US-CENTRAL1"),
								"logging":          map[string]interface{}{},
								"metageneration":   float64(2),
								"name":             string("my-storage-bucket"),
								"owner":            map[string]interface{}{},
								"projectNumber":    float64(6.8478495408e+10),
								"retentionPolicy":  map[string]interface{}{},
								"selfLink":         string("https://www.googleapis.com/storage/v1/b/my-storage-bucket"),
								"storageClass":     string("STANDARD"),
								"timeCreated":      string("2018-07-23T17:30:22.691Z"),
								"updated":          string("2018-07-23T17:30:23.324Z"),
								"versioning":       map[string]interface{}{},
								"website":          map[string]interface{}{},
							},
							"discovery_document_uri": string("https://www.googleapis.com/discovery/v1/apis/storage/v1/rest"),
							"discovery_name":         string("Bucket"),
							"parent":                 string("//cloudresourcemanager.googleapis.com/projects/68478495408"),
							"version":                string("v1"),
						},
					},
				},
				Category: "SECURITY",
			},
			{
				Description:     "//storage.googleapis.com/my-storage-bucket does not have the required logging destination.",
				TargetResources: []string{"//storage.googleapis.com/my-storage-bucket"},
				InsightSubtype:  "GCPStorageLoggingConstraint.require-storage-logging-xx",
				Content: map[string]interface{}{
					"metadata": map[string]interface{}{
						"details": map[string]interface{}{
							"destination_bucket": string(""),
							"resource":           string("//storage.googleapis.com/my-storage-bucket"),
						},
					},
					"resource": map[string]interface{}{
						"ancestry_path": string("organizations/1/folders/2/projects/3"),
						"asset_type":    string("storage.googleapis.com/Bucket"),
						"name":          string("//storage.googleapis.com/my-storage-bucket"),
						"resource": map[string]interface{}{
							"data": map[string]interface{}{
								"acl":              []interface{}{},
								"billing":          map[string]interface{}{},
								"cors":             []interface{}{},
								"defaultObjectAcl": []interface{}{},
								"encryption":       map[string]interface{}{},
								"etag":             string("CAI="),
								"iamConfiguration": map[string]interface{}{"bucketPolicyOnly": map[string]interface{}{}},
								"id":               string("my-storage-bucket"),
								"kind":             string("storage#bucket"),
								"labels":           map[string]interface{}{},
								"lifecycle":        map[string]interface{}{"rule": []interface{}{}},
								"location":         string("US-CENTRAL1"),
								"logging":          map[string]interface{}{},
								"metageneration":   float64(2),
								"name":             string("my-storage-bucket"),
								"owner":            map[string]interface{}{},
								"projectNumber":    float64(6.8478495408e+10),
								"retentionPolicy":  map[string]interface{}{},
								"selfLink":         string("https://www.googleapis.com/storage/v1/b/my-storage-bucket"),
								"storageClass":     string("STANDARD"),
								"timeCreated":      string("2018-07-23T17:30:22.691Z"),
								"updated":          string("2018-07-23T17:30:23.324Z"),
								"versioning":       map[string]interface{}{},
								"website":          map[string]interface{}{},
							},
							"discovery_document_uri": string("https://www.googleapis.com/discovery/v1/apis/storage/v1/rest"),
							"discovery_name":         string("Bucket"),
							"parent":                 string("//cloudresourcemanager.googleapis.com/projects/68478495408"),
							"version":                string("v1"),
						},
					},
				},
				Category: "SECURITY",
			},
		},
		wantViolations: []*validator.Violation{
			{
				Constraint: "CFGCPStorageLoggingConstraint.require-storage-logging",
				Resource:   "//storage.googleapis.com/my-storage-bucket",
				Message:    "//storage.googleapis.com/my-storage-bucket does not have the required logging destination.",
				Metadata: &structpb.Value{
					Kind: &structpb.Value_StructValue{
						StructValue: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"details": &structpb.Value{
									Kind: &structpb.Value_StructValue{
										StructValue: &structpb.Struct{
											Fields: map[string]*structpb.Value{
												"destination_bucket": {
													Kind: &structpb.Value_StringValue{},
												},
												"resource": {
													Kind: &structpb.Value_StringValue{
														StringValue: "//storage.googleapis.com/my-storage-bucket",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			{
				Constraint: "GCPStorageLoggingConstraint.require-storage-logging-xx",
				Resource:   "//storage.googleapis.com/my-storage-bucket",
				Message:    "//storage.googleapis.com/my-storage-bucket does not have the required logging destination.",
				Metadata: &structpb.Value{
					Kind: &structpb.Value_StructValue{
						StructValue: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"details": &structpb.Value{
									Kind: &structpb.Value_StructValue{
										StructValue: &structpb.Struct{
											Fields: map[string]*structpb.Value{
												"destination_bucket": {
													Kind: &structpb.Value_StringValue{},
												},
												"resource": {
													Kind: &structpb.Value_StringValue{
														StringValue: "//storage.googleapis.com/my-storage-bucket",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	},
}

func TestConversion(t *testing.T) {
	v, err := NewValidator(testOptions())
	if err != nil {
		t.Fatal("fatal error:", err)
	}
	for _, tc := range conversionTestCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := v.ReviewJSON(context.Background(), tc.input)
			if err != nil {
				t.Fatal("fatal error:", err)
			}

			insights := result.ToInsights()
			if diff := cmp.Diff(insights, tc.wantInsights); diff != "" {
				t.Errorf("insight mismatch, +got -want\n%s", diff)
			}

			violations, err := result.toViolations()
			if err != nil {
				t.Fatal("fatal error:", err)
			}
			if diff := cmp.Diff(violations, tc.wantViolations); diff != "" {
				t.Errorf("violations mismatch, +got -want\n%s", diff)
			}
		})
	}
}
