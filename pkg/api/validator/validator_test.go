package validator_test

import (
	"testing"

	"github.com/golang/protobuf/jsonpb"
	proto "github.com/golang/protobuf/proto"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"partner-code.googlesource.com/gcv/gcv/pkg/api/validator"
)

// TestJSONMarshaler shows failures that can occur surrounding marshaling
// a proto `Value` type. This issue arose when calling GCV from python.
func TestJSONMarshaler(t *testing.T) {
	cases := []struct {
		name       string
		msg        proto.Message
		shouldFail bool
	}{
		{
			name:       "EmptyAsset",
			msg:        &validator.Asset{},
			shouldFail: false,
		},
		{
			name: "EmptyResourceValue",
			msg: &validator.Asset{
				Resource: &structpb.Value{},
			},
			shouldFail: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := (&jsonpb.Marshaler{}).MarshalToString(c.msg)
			if err != nil && !c.shouldFail {
				t.Error(err)
			}
		})
	}
}

func TestJSONtoJSON(t *testing.T) {
	cases := []struct {
		name       string
		msg        proto.Message
		shouldFail bool
	}{
		{
			name:       "EmptyAsset",
			msg:        &validator.Asset{},
			shouldFail: false,
		},
		{
			name: "EmptyResourceValue",
			msg: &validator.Asset{
				Resource: &structpb.Value{},
			},
			shouldFail: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := (&jsonpb.Marshaler{}).MarshalToString(c.msg)
			if err != nil && !c.shouldFail {
				t.Error(err)
			}
		})
	}
}
