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

package asset

import (
	"testing"

	"cloud.google.com/go/asset/apiv1/assetpb"
	"github.com/GoogleCloudPlatform/config-validator/pkg/api/validator"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConvertResourceToInterface(t *testing.T) {
	testCases := []struct {
		description string
		input       *validator.Asset
		want        interface{}
	}{
		{
			description: "nil input",
			input:       nil,
			want:        nil,
		},
		{
			description: "asset proto preserves underscores",
			input: &validator.Asset{
				Name:      "some name",
				AssetType: "some type",
			},
			want: map[string]interface{}{
				"name":       "some name",
				"asset_type": "some type",
			},
		},
		{
			description: "resource proto preserves underscores",
			input: &validator.Asset{
				Name: "some asset name",
				Resource: &assetpb.Resource{
					DiscoveryName: "some really cool name",
				},
			},
			want: map[string]interface{}{
				"name": "some asset name",
				"resource": map[string]interface{}{
					"discovery_name": "some really cool name",
				},
			},
		},
		{
			description: "resource proto's data preserves underscores",
			input: &validator.Asset{
				Name: "some asset name",
				Resource: &assetpb.Resource{
					Data: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"a_field_with_underscores": {Kind: &structpb.Value_BoolValue{BoolValue: true}},
						},
					},
				},
			},
			want: map[string]interface{}{
				"name": "some asset name",
				"resource": map[string]interface{}{
					"data": map[string]interface{}{
						"a_field_with_underscores": true,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			got, err := ConvertResourceViaJSONToInterface(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tc.want, got, cmp.Comparer(proto.Equal)); diff != "" {
				t.Errorf("%s (-want, +got) %v", tc.description, diff)
			}
		})
	}
}
