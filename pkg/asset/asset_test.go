package asset

import (
	"testing"

	"github.com/golang/protobuf/proto"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/genproto/googleapis/cloud/asset/v1"

	"github.com/forseti-security/config-validator/pkg/api/validator"
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
				Resource: &asset.Resource{
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
				Resource: &asset.Resource{
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
