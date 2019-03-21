package gcv

import (
	"testing"

	"github.com/golang/protobuf/jsonpb"
	structpb "github.com/golang/protobuf/ptypes/struct"
)

func TestCleanProtoValues(t *testing.T) {
	cases := []struct {
		name  string
		value *structpb.Value
		noop  bool
	}{
		{
			name:  "Empty",
			value: &structpb.Value{},
			noop:  false,
		},
		{
			name: "Null",
			value: &structpb.Value{
				Kind: &structpb.Value_NullValue{},
			},
			noop: true,
		},
		{
			name: "Number",
			value: &structpb.Value{
				Kind: &structpb.Value_NumberValue{NumberValue: 0},
			},
			noop: true,
		},
		{
			name: "String",
			value: &structpb.Value{
				Kind: &structpb.Value_StringValue{StringValue: ""},
			},
			noop: true,
		},
		{
			name: "Bool",
			value: &structpb.Value{
				Kind: &structpb.Value_BoolValue{BoolValue: false},
			},
			noop: true,
		},
		{
			name: "ListNilListValue",
			value: &structpb.Value{
				Kind: &structpb.Value_ListValue{
					ListValue: nil,
				},
			},
			noop: true,
		},
		{
			name: "ListNilValues",
			value: &structpb.Value{
				Kind: &structpb.Value_ListValue{
					ListValue: &structpb.ListValue{
						Values: nil,
					},
				},
			},
			noop: true,
		},
		{
			name: "ListLen0",
			value: &structpb.Value{
				Kind: &structpb.Value_ListValue{
					ListValue: &structpb.ListValue{
						Values: []*structpb.Value{},
					},
				},
			},
			noop: true,
		},
		{
			name: "ListWithBadValue",
			value: &structpb.Value{
				Kind: &structpb.Value_ListValue{
					ListValue: &structpb.ListValue{
						Values: []*structpb.Value{
							{},
						},
					},
				},
			},
			noop: false,
		},
		{
			name: "StructNilStructValue",
			value: &structpb.Value{
				Kind: &structpb.Value_StructValue{
					StructValue: nil,
				},
			},
			noop: true,
		},
		{
			name: "StructNilValues",
			value: &structpb.Value{
				Kind: &structpb.Value_StructValue{
					StructValue: &structpb.Struct{
						Fields: nil,
					},
				},
			},
			noop: true,
		},
		{
			name: "StructLen0",
			value: &structpb.Value{
				Kind: &structpb.Value_StructValue{
					StructValue: &structpb.Struct{
						Fields: map[string]*structpb.Value{},
					},
				},
			},
			noop: true,
		},
		{
			name: "StructWithBadValue",
			value: &structpb.Value{
				Kind: &structpb.Value_StructValue{
					StructValue: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"bad": {},
						},
					},
				},
			},
			noop: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pre, err := (&jsonpb.Marshaler{}).MarshalToString(c.value)
			if err == nil && !c.noop {
				t.Fatal("this test should have failed before calling cleanProtoValue()")
			}

			cleanProtoValue(c.value)
			post, err := (&jsonpb.Marshaler{}).MarshalToString(c.value)
			if err != nil {
				t.Fatal(err)
			}

			if c.noop && pre != post {
				t.Fatalf("expected no-op, found difference in json output: pre: %s\npost: %s\n", pre, post)
			}
		})
	}
}
